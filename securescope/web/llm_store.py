from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any

from securescope.core.utils import logger

try:
    from cryptography.fernet import Fernet
except Exception:  # pragma: no cover - optional dependency fallback
    Fernet = None


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


def _to_json(value: Any) -> str:
    import json

    return json.dumps(value or {})


def _from_json(value: str | None) -> dict[str, Any]:
    import json

    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


class SecretCipher:
    """Encrypt/decrypt sensitive values with Fernet where possible."""

    def __init__(self) -> None:
        key_raw = os.environ.get("SECURESCOPE_LLM_KEY", "").encode("utf-8")
        if not key_raw:
            # Stable process-local fallback derived from SECRET_KEY.
            seed = os.environ.get("SECRET_KEY", "securescope-llm-default").encode("utf-8")
            key_raw = base64.urlsafe_b64encode(hashlib.sha256(seed).digest())
        if Fernet:
            self._fernet = Fernet(key_raw)
            self._fallback = False
        else:
            self._fernet = None
            self._fallback = True
            logger.warning("cryptography not available; LLM secrets use obfuscation fallback.")

    def encrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        if self._fernet:
            return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")
        return base64.b64encode(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        try:
            if self._fernet:
                return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")
            return base64.b64decode(value.encode("utf-8")).decode("utf-8")
        except Exception:
            return None


class LLMStore:
    """SQLite store for LLM model and scan records."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.cipher = SecretCipher()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS llm_models (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    model_type TEXT NOT NULL,
                    api_endpoint TEXT,
                    api_key TEXT,
                    model_parameters TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS llm_scan_reports (
                    id TEXT PRIMARY KEY,
                    model_id TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    security_score INTEGER NOT NULL DEFAULT 0,
                    scan_status TEXT NOT NULL DEFAULT 'pending',
                    vulnerabilities_count INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    medium_count INTEGER NOT NULL DEFAULT 0,
                    low_count INTEGER NOT NULL DEFAULT 0,
                    report_json TEXT,
                    report_html TEXT,
                    compliance_status TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(model_id) REFERENCES llm_models(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS llm_vulnerabilities (
                    id TEXT PRIMARY KEY,
                    scan_report_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_component TEXT,
                    remediation_step TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    assigned_to TEXT,
                    due_date TEXT,
                    notes TEXT,
                    jira_ticket TEXT,
                    updated_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_report_id) REFERENCES llm_scan_reports(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS llm_compliance_mappings (
                    id TEXT PRIMARY KEY,
                    scan_report_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    requirement TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence TEXT,
                    FOREIGN KEY(scan_report_id) REFERENCES llm_scan_reports(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS llm_vulnerability_comments (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(vulnerability_id) REFERENCES llm_vulnerabilities(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS llm_activity_log (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    license_id TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    org_id TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS licenses (
                    id TEXT PRIMARY KEY,
                    license_key TEXT NOT NULL UNIQUE,
                    organization_id TEXT,
                    tier TEXT NOT NULL,
                    expires_at TEXT,
                    max_users INTEGER NOT NULL DEFAULT 5,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL
                );
                """
            )
            self._ensure_llm_vulnerability_columns(conn)

    def _ensure_llm_vulnerability_columns(self, conn: sqlite3.Connection) -> None:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(llm_vulnerabilities)").fetchall()}
        needed = {
            "assigned_to": "TEXT",
            "due_date": "TEXT",
            "notes": "TEXT",
            "jira_ticket": "TEXT",
            "updated_at": "TEXT",
        }
        for col, col_type in needed.items():
            if col not in cols:
                conn.execute(f"ALTER TABLE llm_vulnerabilities ADD COLUMN {col} {col_type}")

    def add_model(
        self,
        user_id: str,
        model_name: str,
        model_type: str,
        api_endpoint: str | None,
        api_key: str | None,
        model_parameters: dict[str, Any] | None,
    ) -> str:
        model_id = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO llm_models (id, user_id, model_name, model_type, api_endpoint, api_key, model_parameters, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    model_id,
                    user_id,
                    model_name,
                    model_type,
                    self.cipher.encrypt(api_endpoint),
                    self.cipher.encrypt(api_key),
                    _to_json(model_parameters),
                    now,
                    now,
                ),
            )
        return model_id

    def list_models(self, user_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT m.id, m.model_name, m.model_type, m.updated_at,
                       COALESCE(s.security_score, 0) AS security_score
                FROM llm_models m
                LEFT JOIN llm_scan_reports s
                  ON s.id = (
                        SELECT id
                        FROM llm_scan_reports
                        WHERE model_id = m.id
                        ORDER BY scan_date DESC
                        LIMIT 1
                  )
                WHERE m.user_id = ?
                ORDER BY m.created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [
            {
                "model_id": r["id"],
                "model_name": r["model_name"],
                "model_type": r["model_type"],
                "status": "ready",
                "last_scanned": r["updated_at"],
                "security_score": int(r["security_score"] or 0),
            }
            for r in rows
        ]

    def get_model(self, model_id: str, user_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM llm_models WHERE id = ? AND user_id = ?",
                (model_id, user_id),
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "model_name": row["model_name"],
            "model_type": row["model_type"],
            "api_endpoint": self.cipher.decrypt(row["api_endpoint"]),
            "api_key": self.cipher.decrypt(row["api_key"]),
            "model_parameters": _from_json(row["model_parameters"]),
        }

    def create_scan(self, model_id: str) -> str:
        scan_id = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO llm_scan_reports (id, model_id, scan_date, scan_status, created_at)
                VALUES (?, ?, ?, 'in_progress', ?)
                """,
                (scan_id, model_id, now, now),
            )
        return scan_id

    def complete_scan(self, scan_id: str, report: dict[str, Any], html_report: str) -> None:
        counts = {
            "critical": sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "critical"),
            "high": sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "high"),
            "medium": sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "medium"),
            "low": sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "low"),
        }

        with self._conn() as conn:
            conn.execute(
                """
                UPDATE llm_scan_reports
                SET security_score = ?, scan_status = 'completed', vulnerabilities_count = ?,
                    critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
                    report_json = ?, report_html = ?, compliance_status = ?
                WHERE id = ?
                """,
                (
                    int(report.get("security_score", 0)),
                    int(report.get("vulnerability_count", 0)),
                    counts["critical"],
                    counts["high"],
                    counts["medium"],
                    counts["low"],
                    _to_json(report),
                    html_report,
                    _to_json(report.get("compliance_status", {})),
                    scan_id,
                ),
            )
            for v in report.get("vulnerabilities", []):
                conn.execute(
                    """
                    INSERT INTO llm_vulnerabilities
                    (id, scan_report_id, vulnerability_type, severity, description, affected_component, remediation_step, status, updated_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        scan_id,
                        v.get("type", "unknown"),
                        v.get("severity", "low"),
                        v.get("description", ""),
                        v.get("component"),
                        v.get("remediation"),
                        _utc_now(),
                        _utc_now(),
                    ),
                )
            for framework, status in report.get("compliance_status", {}).items():
                conn.execute(
                    """
                    INSERT INTO llm_compliance_mappings
                    (id, scan_report_id, framework, requirement, status, evidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        scan_id,
                        framework,
                        "LLM security controls baseline",
                        status.get("status", "partial"),
                        _to_json(status),
                    ),
                )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM llm_scan_reports WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        report_json = _from_json(row["report_json"])
        return {
            "scan_id": row["id"],
            "model_id": row["model_id"],
            "status": row["scan_status"],
            "progress": 100 if row["scan_status"] == "completed" else 10,
            "security_score": row["security_score"],
            "vulnerabilities_count": row["vulnerabilities_count"],
            "critical_count": row["critical_count"],
            "high_count": row["high_count"],
            "medium_count": row["medium_count"],
            "low_count": row["low_count"],
            "report_json": report_json,
            "report_html": row["report_html"] or "",
        }

    def update_vulnerability_status(self, vulnerability_id: str, status: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE llm_vulnerabilities SET status = ?, updated_at = ? WHERE id = ?",
                (status, _utc_now(), vulnerability_id),
            )
        return cur.rowcount > 0

    def update_vulnerability(self, vulnerability_id: str, updates: dict[str, Any]) -> bool:
        allowed = {"status", "assigned_to", "due_date", "notes", "jira_ticket"}
        patch = {k: updates[k] for k in allowed if k in updates}
        if not patch:
            return False
        patch["updated_at"] = _utc_now()
        cols = ", ".join([f"{k} = ?" for k in patch.keys()])
        values = list(patch.values()) + [vulnerability_id]
        with self._conn() as conn:
            cur = conn.execute(
                f"UPDATE llm_vulnerabilities SET {cols} WHERE id = ?",
                values,
            )
        return cur.rowcount > 0

    def list_vulnerabilities(self, user_id: str, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        query = """
            SELECT v.id, v.scan_report_id, v.vulnerability_type, v.severity, v.description, v.affected_component,
                   v.remediation_step, v.status, v.assigned_to, v.due_date, v.notes, v.jira_ticket, v.updated_at, v.created_at,
                   m.model_name, m.model_type
            FROM llm_vulnerabilities v
            INNER JOIN llm_scan_reports s ON s.id = v.scan_report_id
            INNER JOIN llm_models m ON m.id = s.model_id
            WHERE m.user_id = ?
        """
        params: list[Any] = [user_id]
        if status:
            query += " AND v.status = ?"
            params.append(status)
        query += " ORDER BY v.created_at DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def add_comment(self, vulnerability_id: str, author: str, comment: str) -> str:
        cid = str(uuid.uuid4())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO llm_vulnerability_comments (id, vulnerability_id, author, comment, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (cid, vulnerability_id, author, comment, now),
            )
        return cid

    def list_comments(self, vulnerability_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, vulnerability_id, author, comment, created_at
                FROM llm_vulnerability_comments
                WHERE vulnerability_id = ?
                ORDER BY created_at DESC
                """,
                (vulnerability_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def log_activity(self, user_id: str, action: str, target_type: str, target_id: str, details: dict[str, Any] | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO llm_activity_log (id, user_id, action, target_type, target_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), user_id, action, target_type, target_id, _to_json(details or {}), _utc_now()),
            )

    def list_activity(self, user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, user_id, action, target_type, target_id, details, created_at
                FROM llm_activity_log
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (user_id, int(limit)),
            ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["details"] = _from_json(item.get("details"))
            out.append(item)
        return out

    # ----- Users / Organizations / Licenses -----
    def create_user(self, username: str, password: str, role: str, org_id: str | None = None) -> str:
        uid = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO app_users (id, username, password, role, org_id, active, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (uid, username, password, role, org_id, _utc_now()),
            )
        return uid

    def authenticate_user(self, username: str, password: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.org_id, o.name AS org_name
                FROM app_users u
                LEFT JOIN organizations o ON o.id = u.org_id
                WHERE u.username = ? AND u.password = ? AND u.active = 1
                """,
                (username, password),
            ).fetchone()
        return dict(row) if row else None

    def list_users(self, org_id: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT u.id, u.username, u.role, u.org_id, u.active, u.created_at, o.name AS organization_name
            FROM app_users u
            LEFT JOIN organizations o ON o.id = u.org_id
        """
        params: list[Any] = []
        if org_id:
            query += " WHERE u.org_id = ?"
            params.append(org_id)
        query += " ORDER BY u.created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.org_id, u.active, o.name AS organization_name
                FROM app_users u
                LEFT JOIN organizations o ON o.id = u.org_id
                WHERE u.id = ?
                """,
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_user_password(self, user_id: str, password: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE app_users SET password = ? WHERE id = ?",
                (password, user_id),
            )
        return cur.rowcount > 0

    def create_organization(self, name: str, admin_username: str, admin_password: str, license_id: str | None = None) -> str:
        oid = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO organizations (id, name, license_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (oid, name, license_id, _utc_now()),
            )
        self.create_user(admin_username, admin_password, role="org_admin", org_id=oid)
        return oid

    def list_organizations(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, name, license_id, created_at
                FROM organizations
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def create_license(self, tier: str, expires_at: str | None, max_users: int, organization_id: str | None = None) -> dict[str, Any]:
        lid = str(uuid.uuid4())
        key = f"SS-{uuid.uuid4().hex[:6].upper()}-{uuid.uuid4().hex[:6].upper()}-{uuid.uuid4().hex[:6].upper()}"
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO licenses (id, license_key, organization_id, tier, expires_at, max_users, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (lid, key, organization_id, tier, expires_at, int(max_users), _utc_now()),
            )
            if organization_id:
                conn.execute(
                    "UPDATE organizations SET license_id = ? WHERE id = ?",
                    (lid, organization_id),
                )
        return {"id": lid, "license_key": key}

    def link_license_organization(self, license_id: str, organization_id: str) -> None:
        with self._conn() as conn:
            # Ensure one-to-one mapping by clearing any old links first.
            conn.execute(
                "UPDATE organizations SET license_id = NULL WHERE license_id = ?",
                (license_id,),
            )
            conn.execute(
                "UPDATE licenses SET organization_id = NULL WHERE organization_id = ?",
                (organization_id,),
            )
            conn.execute(
                "UPDATE licenses SET organization_id = ? WHERE id = ?",
                (organization_id, license_id),
            )
            conn.execute(
                "UPDATE organizations SET license_id = ? WHERE id = ?",
                (license_id, organization_id),
            )

    def unlink_license_organization(self, organization_id: str | None = None, license_id: str | None = None) -> None:
        if not organization_id and not license_id:
            return
        with self._conn() as conn:
            if organization_id:
                conn.execute(
                    "UPDATE licenses SET organization_id = NULL WHERE organization_id = ?",
                    (organization_id,),
                )
                conn.execute(
                    "UPDATE organizations SET license_id = NULL WHERE id = ?",
                    (organization_id,),
                )
            if license_id:
                conn.execute(
                    "UPDATE organizations SET license_id = NULL WHERE license_id = ?",
                    (license_id,),
                )
                conn.execute(
                    "UPDATE licenses SET organization_id = NULL WHERE id = ?",
                    (license_id,),
                )

    def list_licenses(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT l.id, l.license_key, l.organization_id, o.name AS organization_name,
                       l.tier, l.expires_at, l.max_users, l.status, l.created_at
                FROM licenses l
                LEFT JOIN organizations o ON o.id = l.organization_id
                ORDER BY l.created_at DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def fail_scan(self, scan_id: str, reason: str) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE llm_scan_reports
                SET scan_status = 'failed', report_json = ?
                WHERE id = ?
                """,
                (_to_json({"error": reason}), scan_id),
            )

    def list_recent_scans(self, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.model_id, s.scan_date, s.security_score, s.scan_status,
                       s.vulnerabilities_count, s.critical_count, s.high_count, s.medium_count, s.low_count,
                       m.model_name, m.model_type
                FROM llm_scan_reports s
                INNER JOIN llm_models m ON m.id = s.model_id
                WHERE m.user_id = ?
                ORDER BY s.scan_date DESC
                LIMIT ?
                """,
                (user_id, int(limit)),
            ).fetchall()
        return [
            {
                "scan_id": r["id"],
                "model_id": r["model_id"],
                "model_name": r["model_name"],
                "model_type": r["model_type"],
                "scan_date": r["scan_date"],
                "scan_status": r["scan_status"],
                "security_score": int(r["security_score"] or 0),
                "vulnerabilities_count": int(r["vulnerabilities_count"] or 0),
                "critical_count": int(r["critical_count"] or 0),
                "high_count": int(r["high_count"] or 0),
                "medium_count": int(r["medium_count"] or 0),
                "low_count": int(r["low_count"] or 0),
            }
            for r in rows
        ]
