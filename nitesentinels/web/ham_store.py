from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any

try:
    from nitesentinels.core.utils import logger
except Exception:
    import logging
    logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


def _to_json(value: Any) -> str:
    import json
    return json.dumps(value or {})


def _from_json(value: str | None) -> Any:
    import json
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Constants / FSM
# ---------------------------------------------------------------------------
LIFECYCLE_STATES = [
    "procurement", "received", "deployed", "spare",
    "maintenance", "retired", "disposed", "missing", "stolen",
]

LIFECYCLE_TRANSITIONS: dict[str, list[str]] = {
    "procurement": ["received", "disposed"],
    "received":    ["deployed", "spare", "disposed"],
    "deployed":    ["maintenance", "spare", "retired", "missing", "stolen"],
    "spare":       ["deployed", "maintenance", "retired", "disposed"],
    "maintenance": ["deployed", "spare", "retired", "disposed"],
    "retired":     ["disposed"],
    "disposed":    [],
    "missing":     ["deployed", "spare", "retired", "stolen", "disposed"],
    "stolen":      ["missing", "disposed"],
}

ASSET_TYPES = [
    "laptop", "desktop", "server", "workstation", "tablet", "mobile",
    "printer", "scanner", "switch", "router", "firewall", "access_point",
    "ups", "projector", "monitor", "storage", "camera", "badge_reader",
    "pos_terminal", "kiosk", "vm_host", "other",
]

HEALTH_STATES  = ["healthy", "warning", "critical", "unknown", "offline"]
RISK_LEVELS    = ["low", "medium", "high", "critical"]


class HAMStore:
    """SQLite data store for the Hardware Asset Management module.

    Follows the identical pattern to LLMStore: raw sqlite3, row_factory,
    uuid primary keys, CREATE TABLE IF NOT EXISTS for safe schema evolution.
    All queries are parameterised — no string interpolation of user values.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    # ------------------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    # ==================================================================
    # Schema
    # ==================================================================
    def init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                -- -------------------------------------------------------
                -- Core asset table
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_assets (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_tag           TEXT,
                    serial_number       TEXT,
                    name                TEXT NOT NULL,
                    hostname            TEXT,
                    primary_ip          TEXT,
                    mac_address         TEXT,
                    secondary_ips       TEXT,
                    asset_type          TEXT NOT NULL DEFAULT 'other',
                    category            TEXT,
                    sub_category        TEXT,
                    department          TEXT,
                    location            TEXT,
                    building            TEXT,
                    floor               TEXT,
                    room                TEXT,
                    manufacturer        TEXT,
                    model               TEXT,
                    cpu                 TEXT,
                    ram_gb              REAL,
                    disk_gb             REAL,
                    os_name             TEXT,
                    os_version          TEXT,
                    bios_version        TEXT,
                    vlan                TEXT,
                    network_zone        TEXT,
                    last_seen_ip        TEXT,
                    assigned_to         TEXT,
                    assigned_to_email   TEXT,
                    assigned_at         TEXT,
                    manager             TEXT,
                    cost_center         TEXT,
                    purchase_order      TEXT,
                    purchase_price      REAL,
                    purchase_date       TEXT,
                    vendor              TEXT,
                    vendor_contact      TEXT,
                    depreciation_years  INTEGER DEFAULT 3,
                    current_value       REAL,
                    warranty_start      TEXT,
                    warranty_end        TEXT,
                    warranty_type       TEXT,
                    support_contract    TEXT,
                    support_expiry      TEXT,
                    lifecycle_status    TEXT NOT NULL DEFAULT 'deployed',
                    received_at         TEXT,
                    deployed_at         TEXT,
                    retired_at          TEXT,
                    disposed_at         TEXT,
                    disposal_method     TEXT,
                    disposal_notes      TEXT,
                    eol_date            TEXT,
                    health_status       TEXT DEFAULT 'unknown',
                    risk_level          TEXT DEFAULT 'low',
                    risk_score          INTEGER DEFAULT 0,
                    last_health_check   TEXT,
                    last_agent_checkin  TEXT,
                    agent_id            TEXT,
                    agent_version       TEXT,
                    uptime_hours        REAL,
                    patch_level         TEXT,
                    antivirus_status    TEXT,
                    encryption_status   TEXT,
                    firewall_status     TEXT,
                    linked_target_key   TEXT,
                    last_vuln_scan      TEXT,
                    critical_vulns      INTEGER DEFAULT 0,
                    high_vulns          INTEGER DEFAULT 0,
                    qr_token            TEXT UNIQUE,
                    notes               TEXT,
                    tags                TEXT,
                    custom_fields       TEXT,
                    discovered_by       TEXT,
                    created_by          TEXT,
                    updated_by          TEXT,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL,
                    is_deleted          INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_ham_assets_org
                    ON ham_assets(org_id, is_deleted);
                CREATE INDEX IF NOT EXISTS idx_ham_assets_tag
                    ON ham_assets(org_id, asset_tag);
                CREATE INDEX IF NOT EXISTS idx_ham_assets_serial
                    ON ham_assets(org_id, serial_number);
                CREATE INDEX IF NOT EXISTS idx_ham_assets_lifecycle
                    ON ham_assets(lifecycle_status);
                CREATE INDEX IF NOT EXISTS idx_ham_assets_health
                    ON ham_assets(health_status);

                -- -------------------------------------------------------
                -- Append-only audit / change log
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_asset_history (
                    id          TEXT PRIMARY KEY,
                    asset_id    TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    changed_by  TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    field       TEXT,
                    old_value   TEXT,
                    new_value   TEXT,
                    notes       TEXT,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ham_history_asset
                    ON ham_asset_history(asset_id, created_at);

                -- -------------------------------------------------------
                -- Chain-of-custody (append-only)
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_custody_log (
                    id              TEXT PRIMARY KEY,
                    asset_id        TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    from_user       TEXT,
                    to_user         TEXT,
                    from_location   TEXT,
                    to_location     TEXT,
                    transferred_by  TEXT NOT NULL,
                    reason          TEXT,
                    notes           TEXT,
                    acknowledged    INTEGER DEFAULT 0,
                    acknowledged_at TEXT,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ham_custody_asset
                    ON ham_custody_log(asset_id, created_at);

                -- -------------------------------------------------------
                -- Enrolled agents
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_agents (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT,
                    hostname        TEXT,
                    agent_version   TEXT,
                    platform        TEXT,
                    status          TEXT NOT NULL DEFAULT 'active',
                    last_checkin    TEXT,
                    last_ip         TEXT,
                    checkin_count   INTEGER DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    revoked_at      TEXT
                );

                -- -------------------------------------------------------
                -- Agent tokens (enrollment + check-in)
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_agent_tokens (
                    id          TEXT PRIMARY KEY,
                    agent_id    TEXT,
                    org_id      TEXT NOT NULL,
                    token_hash  TEXT NOT NULL UNIQUE,
                    purpose     TEXT NOT NULL DEFAULT 'checkin',
                    is_revoked  INTEGER NOT NULL DEFAULT 0,
                    created_by  TEXT,
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT,
                    last_used   TEXT
                );

                -- -------------------------------------------------------
                -- Agentless discovery jobs
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_discovery_jobs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    target_range    TEXT NOT NULL,
                    scan_type       TEXT NOT NULL DEFAULT 'ping',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    started_by      TEXT,
                    started_at      TEXT,
                    completed_at    TEXT,
                    devices_found   INTEGER DEFAULT 0,
                    error_message   TEXT,
                    created_at      TEXT NOT NULL
                );

                -- -------------------------------------------------------
                -- Discovered devices (pre-approval)
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_discovered_devices (
                    id               TEXT PRIMARY KEY,
                    job_id           TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    ip_address       TEXT,
                    hostname         TEXT,
                    mac_address      TEXT,
                    os_guess         TEXT,
                    open_ports       TEXT,
                    raw_data         TEXT,
                    status           TEXT NOT NULL DEFAULT 'pending',
                    matched_asset_id TEXT,
                    approved_by      TEXT,
                    approved_at      TEXT,
                    rejected_by      TEXT,
                    rejected_at      TEXT,
                    created_at       TEXT NOT NULL
                );

                -- -------------------------------------------------------
                -- Physical audit campaigns
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_audit_campaigns (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    description       TEXT,
                    status            TEXT NOT NULL DEFAULT 'planned',
                    location_filter   TEXT,
                    department_filter TEXT,
                    assigned_to       TEXT,
                    due_date          TEXT,
                    started_at        TEXT,
                    completed_at      TEXT,
                    assets_total      INTEGER DEFAULT 0,
                    assets_verified   INTEGER DEFAULT 0,
                    assets_missing    INTEGER DEFAULT 0,
                    created_by        TEXT,
                    created_at        TEXT NOT NULL
                );

                -- -------------------------------------------------------
                -- Audit results (per-asset)
                -- -------------------------------------------------------
                CREATE TABLE IF NOT EXISTS ham_audit_results (
                    id              TEXT PRIMARY KEY,
                    campaign_id     TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    verified_by     TEXT,
                    verified_at     TEXT,
                    notes           TEXT,
                    condition       TEXT,
                    location_match  INTEGER,
                    created_at      TEXT NOT NULL
                );
            """)
        logger.info("HAM database tables initialised at %s", self.db_path)

    # ==================================================================
    # Internal helpers
    # ==================================================================
    _JSON_FIELDS = ("secondary_ips", "tags", "custom_fields", "open_ports", "raw_data")

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for jf in self._JSON_FIELDS:
            if d.get(jf):
                d[jf] = _from_json(d[jf])
        # Populate aliases for UI and API compatibility
        d["ip_address"] = d.get("primary_ip") or d.get("ip_address")
        d["warranty_expiration"] = d.get("warranty_end") or d.get("warranty_expiration")
        d["purchase_cost"] = d.get("purchase_price") if d.get("purchase_price") is not None else d.get("purchase_cost")
        d["operating_system"] = d.get("os_name") or d.get("operating_system")
        d["assigned_email"] = d.get("assigned_to_email") or d.get("assigned_email")
        d["end_of_life"] = d.get("eol_date") or d.get("end_of_life")
        # Normalize lifecycle for UI
        l_stat = d.get("lifecycle_status")
        if l_stat == "deployed":
            d["lifecycle_status"] = "in_service"
        elif l_stat == "spare":
            d["lifecycle_status"] = "in_stock"
        elif l_stat == "maintenance":
            d["lifecycle_status"] = "in_repair"
        return d

    def _normalize_asset_input(self, data: dict[str, Any]) -> dict[str, Any]:
        out = dict(data)
        if "ip_address" in out and "primary_ip" not in out:
            out["primary_ip"] = out["ip_address"]
        if "warranty_expiration" in out and "warranty_end" not in out:
            out["warranty_end"] = out["warranty_expiration"]
        if "purchase_cost" in out and "purchase_price" not in out:
            out["purchase_price"] = out["purchase_cost"]
        if "operating_system" in out and "os_name" not in out:
            out["os_name"] = out["operating_system"]
        if "assigned_email" in out and "assigned_to_email" not in out:
            out["assigned_to_email"] = out["assigned_email"]
        if "end_of_life" in out and "eol_date" not in out:
            out["eol_date"] = out["end_of_life"]
        if out.get("lifecycle_status") == "in_service":
            out["lifecycle_status"] = "deployed"
        elif out.get("lifecycle_status") == "in_stock":
            out["lifecycle_status"] = "spare"
        elif out.get("lifecycle_status") == "in_repair":
            out["lifecycle_status"] = "maintenance"
        return out

    def _serialise_json_fields(self, data: dict[str, Any]) -> dict[str, Any]:
        out = dict(data)
        for jf in self._JSON_FIELDS:
            if jf in out and isinstance(out[jf], (list, dict)):
                out[jf] = _to_json(out[jf])
        return out

    _ASSET_WRITABLE = frozenset({
        "asset_tag", "serial_number", "name", "hostname", "primary_ip",
        "mac_address", "secondary_ips", "asset_type", "category", "sub_category",
        "department", "location", "building", "floor", "room",
        "manufacturer", "model", "cpu", "ram_gb", "disk_gb",
        "os_name", "os_version", "bios_version", "vlan", "network_zone",
        "assigned_to", "assigned_to_email", "assigned_at", "manager",
        "cost_center", "purchase_order", "purchase_price", "purchase_date",
        "vendor", "vendor_contact", "depreciation_years", "current_value",
        "warranty_start", "warranty_end", "warranty_type",
        "support_contract", "support_expiry",
        "lifecycle_status", "received_at", "deployed_at", "eol_date",
        "disposal_method", "disposal_notes",
        "health_status", "risk_level", "risk_score",
        "last_health_check", "last_agent_checkin", "agent_id", "agent_version",
        "uptime_hours", "patch_level", "antivirus_status",
        "encryption_status", "firewall_status",
        "linked_target_key", "last_vuln_scan", "critical_vulns", "high_vulns",
        "notes", "tags", "custom_fields", "discovered_by",
    })

    # ==================================================================
    # Asset CRUD
    # ==================================================================
    def create_asset(self, org_id: str, data: dict[str, Any], created_by: str) -> str:
        aid = str(uuid.uuid4())
        qr_token = uuid.uuid4().hex
        now = _utc_now()

        norm = self._normalize_asset_input(data)
        fields = {k: v for k, v in norm.items() if k in self._ASSET_WRITABLE}
        fields = self._serialise_json_fields(fields)
        fields.setdefault("lifecycle_status", "deployed")
        fields.setdefault("asset_type", "other")

        cols = ["id", "org_id", "qr_token", "created_by", "updated_by", "created_at", "updated_at"]
        vals: list[Any] = [aid, org_id, qr_token, created_by, created_by, now, now]
        for k, v in fields.items():
            cols.append(k)
            vals.append(v)

        ph = ", ".join("?" * len(vals))
        with self._conn() as conn:
            conn.execute(f"INSERT INTO ham_assets ({', '.join(cols)}) VALUES ({ph})", vals)

        self._log_history(aid, org_id, created_by, "create", notes="Asset created")
        return aid

    def get_asset(self, asset_id: str, org_id: str | None = None) -> dict[str, Any] | None:
        q = "SELECT * FROM ham_assets WHERE id = ? AND is_deleted = 0"
        params: list[Any] = [asset_id]
        if org_id:
            q += " AND org_id = ?"
            params.append(org_id)
        with self._conn() as conn:
            row = conn.execute(q, params).fetchone()
        return self._row_to_dict(row) if row else None

    def get_asset_by_qr_token(self, qr_token: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ham_assets WHERE qr_token = ? AND is_deleted = 0",
                (qr_token,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_assets(
        self,
        org_id: str | None,
        *,
        q: str | None = None,
        lifecycle_status: str | None = None,
        asset_type: str | None = None,
        health_status: str | None = None,
        risk_level: str | None = None,
        department: str | None = None,
        location: str | None = None,
        assigned_to: str | None = None,
        sort_by: str = "name",
        order: str = "asc",
        page: int = 1,
        page_size: int = 25,
        include_retired: bool = False,
        include_disposed: bool = False,
    ) -> dict[str, Any]:
        base = "FROM ham_assets WHERE is_deleted = 0"
        params: list[Any] = []

        if org_id:
            base += " AND org_id = ?"
            params.append(org_id)
        if not include_disposed:
            base += " AND lifecycle_status != 'disposed'"
        if lifecycle_status:
            base += " AND lifecycle_status = ?"
            params.append(lifecycle_status)
        if asset_type:
            base += " AND asset_type = ?"
            params.append(asset_type)
        if health_status:
            base += " AND health_status = ?"
            params.append(health_status)
        if risk_level:
            base += " AND risk_level = ?"
            params.append(risk_level)
        if department:
            base += " AND LOWER(department) LIKE ?"
            params.append(f"%{department.lower()}%")
        if location:
            base += " AND LOWER(location) LIKE ?"
            params.append(f"%{location.lower()}%")
        if assigned_to:
            base += " AND LOWER(assigned_to) LIKE ?"
            params.append(f"%{assigned_to.lower()}%")
        if q:
            base += """ AND (
                LOWER(name) LIKE ? OR LOWER(hostname) LIKE ?
                OR LOWER(asset_tag) LIKE ? OR LOWER(serial_number) LIKE ?
                OR LOWER(primary_ip) LIKE ? OR LOWER(assigned_to) LIKE ?
                OR LOWER(mac_address) LIKE ?
            )"""
            pct = f"%{q.lower()}%"
            params.extend([pct] * 7)

        sort_map = {
            "name": "name", "asset_tag": "asset_tag", "hostname": "hostname",
            "ip": "primary_ip", "lifecycle": "lifecycle_status",
            "health": "health_status", "risk": "risk_score",
            "created": "created_at", "updated": "updated_at",
            "last_seen": "last_agent_checkin", "department": "department",
            "warranty": "warranty_end", "type": "asset_type",
        }
        col = sort_map.get(sort_by, "name")
        direction = "DESC" if order.lower() == "desc" else "ASC"
        page_size = min(max(1, page_size), 500)
        page = max(1, page)
        offset = (page - 1) * page_size

        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) as c {base}", params).fetchone()["c"]
            rows  = conn.execute(
                f"SELECT * {base} ORDER BY {col} {direction} LIMIT ? OFFSET ?",
                params + [page_size, offset]
            ).fetchall()

        assets_list = [self._row_to_dict(r) for r in rows]
        return {
            "items":       assets_list,
            "assets":      assets_list,
            "total":       total,
            "page":        page,
            "page_size":   page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        }

    def update_asset(
        self, asset_id: str, org_id: str | None,
        data: dict[str, Any], updated_by: str
    ) -> bool:
        patch = {k: v for k, v in data.items() if k in self._ASSET_WRITABLE}
        if not patch:
            return False
        patch = self._serialise_json_fields(patch)
        patch["updated_by"] = updated_by
        patch["updated_at"] = _utc_now()

        set_clause = ", ".join(f"{k} = ?" for k in patch)
        vals = list(patch.values()) + [asset_id]
        q = f"UPDATE ham_assets SET {set_clause} WHERE id = ? AND is_deleted = 0"
        if org_id:
            q += " AND org_id = ?"
            vals.append(org_id)
        with self._conn() as conn:
            cur = conn.execute(q, vals)
        return cur.rowcount > 0

    def soft_delete_asset(self, asset_id: str, org_id: str | None, deleted_by: str) -> bool:
        now = _utc_now()
        q = "UPDATE ham_assets SET is_deleted=1, updated_at=?, updated_by=? WHERE id=? AND is_deleted=0"
        params: list[Any] = [now, deleted_by, asset_id]
        if org_id:
            q += " AND org_id = ?"
            params.append(org_id)
        with self._conn() as conn:
            cur = conn.execute(q, params)
        if cur.rowcount > 0:
            self._log_history(asset_id, org_id or "", deleted_by, "delete", notes="Soft-deleted")
            return True
        return False

    # ==================================================================
    # Lifecycle FSM
    # ==================================================================
    def transition_lifecycle(
        self, asset_id: str, org_id: str | None,
        new_status: str, actor: str = "system", notes: str = "",
        **kwargs: Any
    ) -> tuple[bool, str]:
        if "updated_by" in kwargs and actor == "system":
            actor = kwargs["updated_by"]
        if "reason" in kwargs and not notes:
            notes = kwargs["reason"]

        asset = self.get_asset(asset_id, org_id)
        if not asset:
            return False, "Asset not found"
        
        norm_map = {
            "in_service": "deployed",
            "in_stock": "spare",
            "in_repair": "maintenance",
        }
        current_db = norm_map.get(asset.get("lifecycle_status", "deployed"), asset.get("lifecycle_status", "deployed"))
        target_db = norm_map.get(new_status, new_status)

        allowed = LIFECYCLE_TRANSITIONS.get(current_db, [])
        if target_db not in allowed:
            return False, f"Cannot transition '{current_db}' → '{target_db}'. Allowed: {allowed}"
        
        now = _utc_now()
        extra: dict[str, Any] = {"lifecycle_status": target_db}
        if target_db == "retired":   extra["retired_at"]  = now
        if target_db == "disposed":  extra["disposed_at"] = now
        if target_db == "deployed":  extra["deployed_at"] = now
        if target_db == "received":  extra["received_at"] = now
        self.update_asset(asset_id, org_id, extra, actor)
        self._log_history(
            asset_id, org_id or "", actor, "lifecycle_change",
            field="lifecycle_status", old_value=current_db,
            new_value=target_db, notes=notes,
        )
        return True, "ok"

    # ==================================================================
    # Assignment / custody
    # ==================================================================
    def assign_asset(
        self, asset_id: str, org_id: str | None,
        to_user: str | None = None, to_email: str | None = None, actor: str = "system",
        reason: str = "", to_location: str | None = None,
        **kwargs: Any
    ) -> bool:
        to_user = to_user or kwargs.get("new_assigned_to") or ""
        to_email = to_email or kwargs.get("assigned_email")
        to_location = to_location or kwargs.get("new_location")
        actor = kwargs.get("updated_by") or actor
        reason = kwargs.get("notes") or reason
        new_dept = kwargs.get("new_department")

        asset = self.get_asset(asset_id, org_id)
        if not asset:
            return False
        from_user     = asset.get("assigned_to")
        from_location = asset.get("location")
        now = _utc_now()
        patch: dict[str, Any] = {
            "assigned_to": to_user,
            "assigned_to_email": to_email or "",
            "assigned_at": now,
        }
        if to_location:
            patch["location"] = to_location
        if new_dept:
            patch["department"] = new_dept
        self.update_asset(asset_id, org_id, patch, actor)
        cid = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_custody_log
                (id,asset_id,org_id,from_user,to_user,from_location,to_location,
                 transferred_by,reason,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (cid, asset_id, org_id or "", from_user, to_user,
                 from_location, to_location, actor, reason, now),
            )
        return True

    def get_custody_log(self, asset_id: str, org_id: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM ham_custody_log WHERE asset_id = ?"
        params: list[Any] = [asset_id]
        if org_id:
            q += " AND org_id = ?"
            params.append(org_id)
        q += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["custodian"] = d.get("to_user")
            d["timestamp"] = d.get("created_at")
            d["authorized_by"] = d.get("transferred_by")
            d["notes"] = d.get("reason")
            out.append(d)
        return out

    # ==================================================================
    # History logging
    # ==================================================================
    def _log_history(
        self, asset_id: str, org_id: str, changed_by: str, action: str,
        field: str | None = None, old_value: str | None = None,
        new_value: str | None = None, notes: str | None = None,
    ) -> None:
        try:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ham_asset_history
                    (id,asset_id,org_id,changed_by,action,field,old_value,new_value,notes,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), asset_id, org_id, changed_by,
                     action, field, old_value, new_value, notes, _utc_now()),
                )
        except Exception as exc:
            logger.warning("HAM history log failed: %s", exc)

    def get_asset_history(self, asset_id: str, org_id: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM ham_asset_history WHERE asset_id = ?"
        params: list[Any] = [asset_id]
        if org_id:
            q += " AND org_id = ?"
            params.append(org_id)
        q += " ORDER BY created_at DESC LIMIT 300"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    # ==================================================================
    # Dashboard KPIs
    # ==================================================================
    def get_dashboard_kpis(self, org_id: str | None) -> dict[str, Any]:
        base = "FROM ham_assets WHERE is_deleted = 0"
        params: list[Any] = []
        if org_id:
            base += " AND org_id = ?"
            params.append(org_id)
        now_str  = datetime.utcnow().strftime("%Y-%m-%d")
        warn_str = (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d")

        with self._conn() as conn:
            def _count(where: str, extra: list = []) -> int:
                r = conn.execute(f"SELECT COUNT(*) as c {base} {where}", params + list(extra)).fetchone()
                return r["c"] if r else 0

            kpis = {
                "total":                _count(""),
                "total_assets":         _count(""),
                "active":               _count("AND lifecycle_status IN ('deployed', 'in_service')"),
                "active_assets":        _count("AND lifecycle_status IN ('deployed', 'in_service')"),
                "spare":                _count("AND lifecycle_status IN ('spare', 'in_stock')"),
                "in_stock":             _count("AND lifecycle_status IN ('spare', 'in_stock')"),
                "maintenance":          _count("AND lifecycle_status IN ('maintenance', 'in_repair')"),
                "in_repair":            _count("AND lifecycle_status IN ('maintenance', 'in_repair')"),
                "retired":              _count("AND lifecycle_status='retired'"),
                "disposed":             _count("AND lifecycle_status='disposed'"),
                "missing":              _count("AND lifecycle_status IN ('missing','stolen')"),
                "unassigned":           _count("AND (assigned_to IS NULL OR assigned_to='') AND lifecycle_status IN ('deployed', 'in_service')"),
                "health_healthy":       _count("AND health_status='healthy'"),
                "health_warning":       _count("AND health_status='warning'"),
                "health_critical":      _count("AND health_status='critical'"),
                "health_offline":       _count("AND health_status='offline'"),
                "unhealthy_assets":     _count("AND health_status IN ('warning', 'critical', 'offline')"),
                "risk_critical":        _count("AND risk_level='critical'"),
                "critical_risk":        _count("AND risk_level='critical'"),
                "risk_high":            _count("AND risk_level='high'"),
                "high_risk":            _count("AND risk_level='high'"),
                "warranty_expiring":    _count("AND warranty_end>=? AND warranty_end<=?", [now_str, warn_str]),
                "warranty_expiring_soon": _count("AND warranty_end>=? AND warranty_end<=?", [now_str, warn_str]),
                "warranty_expired":     _count("AND warranty_end<? AND warranty_end IS NOT NULL", [now_str]),
                "eol_soon":             _count("AND eol_date>=? AND eol_date<=?", [now_str, warn_str]),
                "by_health": {
                    "healthy": _count("AND health_status='healthy'"),
                    "warning": _count("AND health_status='warning'"),
                    "critical": _count("AND health_status='critical'"),
                    "unknown": _count("AND (health_status IS NULL OR health_status='unknown')"),
                },
                "by_risk_level": {
                    "low": _count("AND (risk_level='low' OR risk_level IS NULL)"),
                    "medium": _count("AND risk_level='medium'"),
                    "high": _count("AND risk_level='high'"),
                    "critical": _count("AND risk_level='critical'"),
                }
            }
            rows = conn.execute(f"SELECT asset_type, COUNT(*) as c {base} GROUP BY asset_type", params).fetchall()
            kpis["by_type"] = {r["asset_type"]: r["c"] for r in rows}

            rows = conn.execute(f"SELECT lifecycle_status, COUNT(*) as c {base} GROUP BY lifecycle_status", params).fetchall()
            status_map = {}
            for r in rows:
                st = r["lifecycle_status"]
                if st == "deployed": st = "in_service"
                elif st == "spare": st = "in_stock"
                elif st == "maintenance": st = "in_repair"
                status_map[st] = status_map.get(st, 0) + r["c"]
            kpis["by_lifecycle"] = status_map
            kpis["by_status"] = status_map

            rows = conn.execute(
                f"SELECT department, COUNT(*) as c {base} AND department IS NOT NULL GROUP BY department ORDER BY c DESC LIMIT 10",
                params
            ).fetchall()
            kpis["by_department"] = {r["department"]: r["c"] for r in rows}

            # Recent activity
            rows = conn.execute(
                """SELECT h.action, h.field, h.new_value, h.changed_by, h.created_at, a.name as asset_name
                FROM ham_asset_history h
                JOIN ham_assets a ON a.id = h.asset_id
                WHERE a.is_deleted = 0
                """ + ("AND a.org_id = ?" if org_id else "") + """
                ORDER BY h.created_at DESC LIMIT 10""",
                ([org_id] if org_id else [])
            ).fetchall()
            kpis["recent_activity"] = [dict(r) for r in rows]

        return kpis

    # ==================================================================
    # Warranty
    # ==================================================================
    def get_warranty_report(self, org_id: str | None, days_ahead: int = 90) -> dict[str, Any]:
        base = "FROM ham_assets WHERE is_deleted = 0"
        params: list[Any] = []
        if org_id:
            base += " AND org_id = ?"
            params.append(org_id)
        now_str    = datetime.utcnow().strftime("%Y-%m-%d")
        future_str = (datetime.utcnow() + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
        with self._conn() as conn:
            expiring = conn.execute(
                f"SELECT * {base} AND warranty_end >= ? AND warranty_end <= ? ORDER BY warranty_end ASC",
                params + [now_str, future_str]
            ).fetchall()
            expired = conn.execute(
                f"SELECT * {base} AND warranty_end < ? AND warranty_end IS NOT NULL ORDER BY warranty_end DESC LIMIT 50",
                params + [now_str]
            ).fetchall()
        return {
            "days_ahead": days_ahead,
            "expiring":   [self._row_to_dict(r) for r in expiring],
            "expired":    [self._row_to_dict(r) for r in expired],
        }

    # ==================================================================
    # Ghost-asset reconciliation
    # ==================================================================
    def get_ghost_assets(self, org_id: str | None, offline_days: int = 30) -> list[dict[str, Any]]:
        cutoff = (datetime.utcnow() - timedelta(days=offline_days)).isoformat()
        q = """SELECT * FROM ham_assets WHERE is_deleted=0
               AND lifecycle_status='deployed'
               AND agent_id IS NOT NULL
               AND (last_agent_checkin IS NULL OR last_agent_checkin < ?)"""
        params: list[Any] = [cutoff]
        if org_id:
            q += " AND org_id = ?"
            params.append(org_id)
        q += " ORDER BY last_agent_checkin ASC LIMIT 200"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ==================================================================
    # Agent management
    # ==================================================================
    def create_agent_enrollment_token(self, org_id: str, created_by: str) -> dict[str, Any]:
        raw_token  = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        tok_id     = str(uuid.uuid4())
        now        = _utc_now()
        expires    = (datetime.utcnow() + timedelta(days=7)).isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_agent_tokens
                (id,agent_id,org_id,token_hash,purpose,is_revoked,created_by,created_at,expires_at)
                VALUES (?,NULL,?,?,'enrollment',0,?,?,?)""",
                (tok_id, org_id, token_hash, created_by, now, expires),
            )
        return {"token_id": tok_id, "token": raw_token, "raw_token": raw_token, "expires_at": expires}

    def validate_agent_token(self, raw_token: str) -> dict[str, Any] | None:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM ham_agent_tokens
                WHERE token_hash=? AND is_revoked=0
                AND (expires_at IS NULL OR expires_at > ?)""",
                (token_hash, _utc_now()),
            ).fetchone()
            if not row:
                return None
            conn.execute("UPDATE ham_agent_tokens SET last_used=? WHERE id=?", (_utc_now(), row["id"]))
        return dict(row)

    def register_agent(
        self, org_id: str, enrollment_token_id: str,
        hostname: str, platform: str, version: str,
    ) -> str:
        agent_id = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_agents
                (id,org_id,hostname,agent_version,platform,status,last_checkin,created_at)
                VALUES (?,?,?,?,?,'active',?,?)""",
                (agent_id, org_id, hostname, version, platform, now, now),
            )
            conn.execute(
                "UPDATE ham_agent_tokens SET agent_id=?, purpose='checkin' WHERE id=?",
                (agent_id, enrollment_token_id),
            )
        return agent_id

    def process_agent_checkin(self, agent_id: str, telemetry: dict[str, Any]) -> bool:
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """UPDATE ham_agents SET last_checkin=?, last_ip=?,
                agent_version=?, checkin_count=checkin_count+1
                WHERE id=?""",
                (now, telemetry.get("ip"), telemetry.get("agent_version", "unknown"), agent_id),
            )
            agent = conn.execute("SELECT * FROM ham_agents WHERE id=?", (agent_id,)).fetchone()
            if not agent:
                return False
            asset_id = agent["asset_id"]
        if asset_id:
            patch: dict[str, Any] = {k: telemetry.get(k) for k in (
                "hostname", "os_name", "os_version", "cpu", "ram_gb", "disk_gb",
                "uptime_hours", "patch_level", "antivirus_status",
                "encryption_status", "firewall_status",
            ) if telemetry.get(k) is not None}
            patch["last_agent_checkin"] = now
            patch["agent_version"]      = telemetry.get("agent_version")
            if telemetry.get("ip"):
                patch["primary_ip"] = telemetry["ip"]
            with self._conn() as conn:
                ag = conn.execute("SELECT org_id FROM ham_agents WHERE id=?", (agent_id,)).fetchone()
                org_id = ag["org_id"] if ag else None
            self.update_asset(asset_id, org_id, patch, "agent")
        return True

    def list_agents(self, org_id: str | None) -> list[dict[str, Any]]:
        q = "SELECT * FROM ham_agents WHERE 1=1"
        params: list[Any] = []
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        q += " ORDER BY last_checkin DESC"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def revoke_agent(self, agent_id: str, org_id: str | None) -> bool:
        now = _utc_now()
        q = "UPDATE ham_agents SET status='revoked', revoked_at=? WHERE id=?"
        params: list[Any] = [now, agent_id]
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        with self._conn() as conn:
            conn.execute("UPDATE ham_agent_tokens SET is_revoked=1 WHERE agent_id=?", (agent_id,))
            cur = conn.execute(q, params)
        return cur.rowcount > 0

    def delete_agent(self, agent_id: str, org_id: str | None) -> bool:
        q = "DELETE FROM ham_agents WHERE id=?"
        params: list[Any] = [agent_id]
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        with self._conn() as conn:
            conn.execute("DELETE FROM ham_agent_tokens WHERE agent_id=?", (agent_id,))
            cur = conn.execute(q, params)
        return cur.rowcount > 0

    def rotate_agent_token(self, agent_id: str, org_id: str | None, rotated_by: str) -> dict[str, Any]:
        # Revoke current, issue new
        with self._conn() as conn:
            conn.execute("UPDATE ham_agent_tokens SET is_revoked=1 WHERE agent_id=?", (agent_id,))
        raw  = secrets.token_urlsafe(32)
        thsh = hashlib.sha256(raw.encode()).hexdigest()
        tok_id = str(uuid.uuid4())
        now  = _utc_now()
        exp  = (datetime.utcnow() + timedelta(days=365)).isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_agent_tokens
                (id,agent_id,org_id,token_hash,purpose,is_revoked,created_by,created_at,expires_at)
                VALUES (?,?,?,?,'checkin',0,?,?,?)""",
                (tok_id, agent_id, org_id or "", thsh, rotated_by, now, exp),
            )
        return {"token_id": tok_id, "raw_token": raw, "expires_at": exp}

    # ==================================================================
    # Agentless discovery
    # ==================================================================
    def create_discovery_job(
        self, org_id: str, target_range: str, scan_type: str, started_by: str
    ) -> str:
        job_id = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_discovery_jobs
                (id,org_id,target_range,scan_type,status,started_by,started_at,created_at)
                VALUES (?,?,?,?,'running',?,?,?)""",
                (job_id, org_id, target_range, scan_type, started_by, now, now),
            )
        return job_id

    def complete_discovery_job(self, job_id: str, devices: list[dict[str, Any]]) -> None:
        now = _utc_now()
        with self._conn() as conn:
            job = conn.execute("SELECT org_id FROM ham_discovery_jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                return
            org_id = job["org_id"]
            for dev in devices:
                did = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO ham_discovered_devices
                    (id,job_id,org_id,ip_address,hostname,mac_address,os_guess,open_ports,raw_data,status,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,'pending',?)""",
                    (did, job_id, org_id, dev.get("ip"), dev.get("hostname"),
                     dev.get("mac"), dev.get("os_guess"),
                     _to_json(dev.get("open_ports", [])), _to_json(dev), now),
                )
            conn.execute(
                "UPDATE ham_discovery_jobs SET status='completed', completed_at=?, devices_found=? WHERE id=?",
                (now, len(devices), job_id),
            )

    def fail_discovery_job(self, job_id: str, error: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE ham_discovery_jobs SET status='failed', completed_at=?, error_message=? WHERE id=?",
                (_utc_now(), error, job_id),
            )

    def list_discovery_jobs(self, org_id: str | None, limit: int = 20) -> list[dict[str, Any]]:
        q = "SELECT * FROM ham_discovery_jobs WHERE 1=1"
        params: list[Any] = []
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        q += f" ORDER BY created_at DESC LIMIT {min(int(limit), 100)}"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get_discovery_job(self, job_id: str, org_id: str | None = None) -> dict[str, Any] | None:
        q = "SELECT * FROM ham_discovery_jobs WHERE id=?"
        params: list[Any] = [job_id]
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        with self._conn() as conn:
            job_row = conn.execute(q, params).fetchone()
            if not job_row:
                return None
            job = dict(job_row)
            devs = conn.execute(
                "SELECT * FROM ham_discovered_devices WHERE job_id=? ORDER BY created_at ASC",
                (job_id,)
            ).fetchall()
        job["devices"] = [self._row_to_dict(d) for d in devs]
        return job

    def approve_discovered_device(
        self, device_id: str, org_id: str | None,
        approved_by: str, asset_data: dict[str, Any],
    ) -> str:
        with self._conn() as conn:
            dev = conn.execute("SELECT * FROM ham_discovered_devices WHERE id=?", (device_id,)).fetchone()
            if not dev:
                raise ValueError("Device not found")
        merged = {
            "hostname":      dev["hostname"],
            "primary_ip":    dev["ip_address"],
            "mac_address":   dev["mac_address"],
            "discovered_by": "agentless",
            **asset_data,
        }
        asset_id = self.create_asset(org_id or dev["org_id"], merged, approved_by)
        with self._conn() as conn:
            conn.execute(
                "UPDATE ham_discovered_devices SET status='approved', approved_by=?, approved_at=?, matched_asset_id=? WHERE id=?",
                (approved_by, _utc_now(), asset_id, device_id),
            )
        return asset_id

    def reject_discovered_device(self, device_id: str, rejected_by: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE ham_discovered_devices SET status='rejected', rejected_by=?, rejected_at=? WHERE id=?",
                (rejected_by, _utc_now(), device_id),
            )
        return cur.rowcount > 0

    # ==================================================================
    # Audit campaigns
    # ==================================================================
    def create_audit_campaign(
        self, org_id: str, name: str, data: dict[str, Any], created_by: str
    ) -> str:
        cid = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ham_audit_campaigns
                (id,org_id,name,description,status,location_filter,department_filter,
                 assigned_to,due_date,created_by,created_at)
                VALUES (?,?,?,?,'planned',?,?,?,?,?,?)""",
                (cid, org_id, name, data.get("description"), data.get("location_filter"),
                 data.get("department_filter"), data.get("assigned_to"),
                 data.get("due_date"), created_by, now),
            )
        return cid

    def list_audit_campaigns(self, org_id: str | None) -> list[dict[str, Any]]:
        q = "SELECT * FROM ham_audit_campaigns WHERE 1=1"
        params: list[Any] = []
        if org_id:
            q += " AND org_id=?"
            params.append(org_id)
        q += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def submit_audit_result(
        self, campaign_id: str, asset_id: str, org_id: str,
        actor: str, data: dict[str, Any],
    ) -> str:
        rid = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ham_audit_results
                (id,campaign_id,asset_id,org_id,status,verified_by,verified_at,
                 notes,condition,location_match,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, campaign_id, asset_id, org_id,
                 data.get("status", "verified"), actor, now,
                 data.get("notes"), data.get("condition"),
                 1 if data.get("location_match") else 0, now),
            )
            conn.execute(
                """UPDATE ham_audit_campaigns SET
                assets_verified=(SELECT COUNT(*) FROM ham_audit_results WHERE campaign_id=? AND status='verified'),
                assets_missing=(SELECT COUNT(*) FROM ham_audit_results WHERE campaign_id=? AND status='missing')
                WHERE id=?""",
                (campaign_id, campaign_id, campaign_id),
            )
        return rid

    # ==================================================================
    # CSV import / export
    # ==================================================================
    CSV_FIELDS = [
        "asset_tag", "name", "serial_number", "asset_type", "manufacturer", "model",
        "hostname", "primary_ip", "mac_address", "department", "location",
        "assigned_to", "assigned_to_email", "purchase_date", "purchase_price",
        "warranty_start", "warranty_end", "lifecycle_status", "os_name", "notes",
    ]

    def export_csv(self, org_id: str | None) -> str:
        result = self.list_assets(
            org_id, page_size=10000, include_retired=True, include_disposed=True
        )
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self.CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for asset in result["items"]:
            writer.writerow({f: asset.get(f, "") for f in self.CSV_FIELDS})
        return buf.getvalue()

    def import_csv(
        self, org_id: str, csv_content: str, imported_by: str
    ) -> dict[str, Any]:
        reader  = csv.DictReader(io.StringIO(csv_content))
        created = 0
        skipped = 0
        errors: list[str] = []
        for i, row in enumerate(reader, start=2):
            name = (row.get("name") or "").strip()
            if not name:
                errors.append(f"Row {i}: 'name' is required — skipped")
                skipped += 1
                continue
            tag = (row.get("asset_tag") or "").strip() or None
            if tag:
                with self._conn() as conn:
                    ex = conn.execute(
                        "SELECT id FROM ham_assets WHERE org_id=? AND asset_tag=? AND is_deleted=0",
                        (org_id, tag)
                    ).fetchone()
                    if ex:
                        errors.append(f"Row {i}: asset_tag '{tag}' already exists — skipped")
                        skipped += 1
                        continue
            try:
                self.create_asset(org_id, dict(row), imported_by)
                created += 1
            except Exception as exc:
                errors.append(f"Row {i}: {exc}")
                skipped += 1
        return {"created": created, "skipped": skipped, "errors": errors}

    # ==================================================================
    # Bulk operations
    # ==================================================================
    def bulk_update(
        self, org_id: str | None, asset_ids: list[str],
        update_data: dict[str, Any], actor: str,
    ) -> dict[str, Any]:
        ok = failed = 0
        for aid in asset_ids:
            try:
                if self.update_asset(aid, org_id, update_data, actor):
                    ok += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
        return {"updated": ok, "failed": failed, "total": len(asset_ids)}

    def bulk_lifecycle(
        self, org_id: str | None, asset_ids: list[str],
        new_status: str, actor: str, notes: str = "",
    ) -> dict[str, Any]:
        ok = failed = 0
        errors: list[str] = []
        for aid in asset_ids:
            success, msg = self.transition_lifecycle(aid, org_id, new_status, actor, notes)
            if success:
                ok += 1
            else:
                failed += 1
                errors.append(f"{aid}: {msg}")
        return {"ok": ok, "failed": failed, "errors": errors}
