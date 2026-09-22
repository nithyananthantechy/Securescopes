"""
NiteSentinel Hardware Asset Management — Flask Blueprint
=========================================================
All HAM page routes and REST API endpoints.

URL structure:
  Page routes  →  /ham/...          (render HTML via Jinja2)
  API routes   →  /api/ham/...      (return JSON)

Security:
  - All routes require @login_required (from app.py)
  - POST/PUT/DELETE require @secure_post (CSRF)
  - Permission checks via has_permission() (from app.py)
  - Tenant isolation via org_filter() (from app.py)
  - No shell execution from user-controlled fields
  - All SQL queries parameterised (no interpolation)
"""
from __future__ import annotations

import io
import json
import threading
import traceback
from datetime import datetime
from functools import wraps
from typing import Any

from flask import (
    Blueprint, Response, jsonify, redirect, render_template,
    request, send_file, session, url_for,
)

# Lazy imports from app to avoid circular imports
def _app_mod():
    from nitesentinels.web import app as _app_module
    return _app_module

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from nitesentinels.web.app import login_required as _lr
        return _lr(f)(*args, **kwargs)
    return decorated

def secure_post(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from nitesentinels.web.app import secure_post as _sp
        return _sp(f)(*args, **kwargs)
    return decorated

def _has_permission(perm: str) -> bool:
    from nitesentinels.web.app import has_permission
    return has_permission(session.get("org_id"), perm)

def _org_filter() -> str | None:
    from nitesentinels.web.app import org_filter
    return org_filter()

def _csrf_token() -> str:
    from nitesentinels.web.app import _csrf_token as _ct
    return _ct()

def _is_super_admin() -> bool:
    from nitesentinels.web.app import _is_super_admin as _isa
    return _isa()

def _current_user() -> str:
    return session.get("username") or session.get("user_id") or "anonymous"

def _get_config() -> dict:
    from nitesentinels.web.app import config
    return config or {}

def _get_stored_scan_results() -> dict:
    try:
        from nitesentinels.web.app import stored_scan_results
        return stored_scan_results
    except Exception:
        return {}

def _get_all_findings() -> list:
    """Extract all findings from stored_scan_results with target_key annotation."""
    results = []
    for target_key, target_data in _get_stored_scan_results().items():
        for finding in (target_data.get("findings") or []):
            f = dict(finding)
            f["target_key"] = target_key
            results.append(f)
    return results

def _get_extract_findings():
    return _get_all_findings


# ---------------------------------------------------------------------------
ham_bp = Blueprint("ham", __name__, url_prefix="")


def _ham_store():
    """Get the HAMStore singleton from the app module."""
    from nitesentinels.web.app import ham_store
    return ham_store


def require_ham_perm(perm: str):
    """Decorator — abort 403 if user lacks permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not _has_permission(perm):
                return jsonify({"error": "Forbidden: insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def _template_ctx(**extra) -> dict:
    """Common template context variables."""
    cfg = _get_config()
    return {
        "username":       session.get("username", "operator"),
        "role":           session.get("role", "viewer"),
        "is_super_admin": _is_super_admin(),
        "org_name":       cfg.get("branding", {}).get("organization_name", "NiTechSpark"),
        "client_name":    cfg.get("branding", {}).get("client_name", "Default Client"),
        "csrf_token":     _csrf_token(),
        "demo_mode":      False,
        **extra,
    }


# ===========================================================================
# Page Routes (HTML)
# ===========================================================================

@ham_bp.route("/ham/")
@ham_bp.route("/ham")
@login_required
def ham_dashboard_page():
    return render_template("ham_dashboard.html", **_template_ctx())


@ham_bp.route("/ham/assets")
@login_required
def ham_assets_page():
    return render_template("ham_assets.html", **_template_ctx())


@ham_bp.route("/ham/assets/<asset_id>")
@login_required
def ham_asset_detail_page(asset_id: str):
    store = _ham_store()
    org_id = _org_filter()
    asset = store.get_asset(asset_id, org_id)
    if not asset:
        return redirect(url_for("ham.ham_assets_page"))
    return render_template("ham_asset_detail.html", asset=asset, **_template_ctx())


@ham_bp.route("/ham/discover")
@login_required
def ham_discover_page():
    return render_template("ham_discover.html", **_template_ctx())


@ham_bp.route("/ham/assignments")
@login_required
def ham_assignments_page():
    return render_template("ham_assets.html", filter_mode="unassigned", **_template_ctx())


@ham_bp.route("/ham/lifecycle")
@login_required
def ham_lifecycle_page():
    return render_template("ham_assets.html", filter_mode="lifecycle", **_template_ctx())


@ham_bp.route("/ham/warranty")
@login_required
def ham_warranty_page():
    return render_template("ham_warranty.html", **_template_ctx())


@ham_bp.route("/ham/health")
@login_required
def ham_health_page():
    return render_template("ham_assets.html", filter_mode="health", **_template_ctx())


@ham_bp.route("/ham/audit")
@login_required
def ham_audit_page():
    return render_template("ham_audit.html", **_template_ctx())


@ham_bp.route("/ham/custody")
@login_required
def ham_custody_page():
    return render_template("ham_custody.html", **_template_ctx())


@ham_bp.route("/ham/retired")
@login_required
def ham_retired_page():
    return render_template("ham_assets.html", filter_mode="retired", **_template_ctx())


@ham_bp.route("/ham/reports")
@login_required
def ham_reports_page():
    return render_template("ham_reports.html", **_template_ctx())


@ham_bp.route("/ham/settings")
@login_required
def ham_settings_page():
    return render_template("ham_settings.html", **_template_ctx())


@ham_bp.route("/ham/agents")
@login_required
def ham_agents_page():
    return render_template("ham_agents.html", **_template_ctx())


# ===========================================================================
# Public QR landing (no login required — minimal info only)
# ===========================================================================

@ham_bp.route("/api/ham/public/asset/<qr_token>")
def ham_public_qr(qr_token: str):
    """Public page rendered when a QR code is scanned. Shows minimal, non-sensitive info."""
    store = _ham_store()
    asset = store.get_asset_by_qr_token(qr_token)
    if not asset:
        return render_template("ham_qr_public.html", asset=None, error="Asset not found"), 404
    # Return only safe fields — never expose internal IDs, org details, or credentials
    safe = {
        "name":             asset.get("name"),
        "asset_tag":        asset.get("asset_tag"),
        "asset_type":       asset.get("asset_type"),
        "manufacturer":     asset.get("manufacturer"),
        "model":            asset.get("model"),
        "department":       asset.get("department"),
        "location":         asset.get("location"),
        "assigned_to":      asset.get("assigned_to"),
        "lifecycle_status": asset.get("lifecycle_status"),
        "support_contract": asset.get("support_contract"),
    }
    return render_template("ham_qr_public.html", asset=safe, error=None)


# ===========================================================================
# API — Dashboard KPIs
# ===========================================================================

@ham_bp.route("/api/ham/dashboard")
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_dashboard():
    try:
        store = _ham_store()
        org_id = _org_filter()
        kpis = store.get_dashboard_kpis(org_id)
        return jsonify({"ok": True, **kpis})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Assets CRUD
# ===========================================================================

@ham_bp.route("/api/ham/assets", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_list_assets():
    try:
        store  = _ham_store()
        org_id = _org_filter()
        result = store.list_assets(
            org_id,
            q=request.args.get("q") or request.args.get("search"),
            lifecycle_status=request.args.get("lifecycle") or request.args.get("lifecycle_status"),
            asset_type=request.args.get("type") or request.args.get("asset_type"),
            health_status=request.args.get("health") or request.args.get("health_status"),
            risk_level=request.args.get("risk") or request.args.get("risk_level"),
            department=request.args.get("department"),
            location=request.args.get("location"),
            assigned_to=request.args.get("assigned_to"),
            sort_by=request.args.get("sort_by", "name"),
            order=request.args.get("order") or request.args.get("sort_dir", "asc"),
            page=max(1, int(request.args.get("page", 1))),
            page_size=min(200, max(1, int(request.args.get("page_size") or request.args.get("limit") or 25))),
            include_retired="1" in (request.args.get("include_retired", "")),
            include_disposed="1" in (request.args.get("include_disposed", "")),
        )
        return jsonify(result)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.create")
@secure_post
def api_ham_create_asset():
    try:
        store  = _ham_store()
        org_id = session.get("org_id") or _org_filter() or "global"
        data   = request.get_json() or {}
        name   = (data.get("name") or data.get("asset_name") or "").strip()
        if not name:
            return jsonify({"error": "Asset name is required"}), 400
        data["name"] = name
        actor    = _current_user()
        asset_id = store.create_asset(org_id, data, actor)
        return jsonify({"ok": True, "asset_id": asset_id}), 201
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_get_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        asset  = store.get_asset(asset_id, org_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        return jsonify(asset)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>", methods=["PUT"])
@login_required
@require_ham_perm("ham.assets.edit")
@secure_post
def api_ham_update_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        data   = request.get_json() or {}
        actor  = _current_user()
        ok = store.update_asset(asset_id, org_id, data, actor)
        if not ok:
            return jsonify({"error": "Asset not found or no changes"}), 404
        # Re-evaluate health + risk after update
        _recompute_health_risk(store, asset_id, org_id, actor)
        return jsonify({"ok": True})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>", methods=["DELETE"])
@login_required
@require_ham_perm("ham.assets.delete")
@secure_post
def api_ham_delete_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        actor  = _current_user()
        ok = store.soft_delete_asset(asset_id, org_id, actor)
        if not ok:
            return jsonify({"error": "Asset not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/history", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_asset_history(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        history = store.get_asset_history(asset_id, org_id)
        return jsonify({"items": history, "total": len(history)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/findings", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_asset_findings(asset_id: str):
    """Return security findings linked to this asset via linked_target_key."""
    try:
        store  = _ham_store()
        org_id = _org_filter()
        asset  = store.get_asset(asset_id, org_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        linked_key = asset.get("linked_target_key")
        if not linked_key:
            return jsonify({"findings": [], "linked_target": None})
        _extract_findings = _get_extract_findings()
        all_findings = _extract_findings()
        asset_findings = [f for f in all_findings if f.get("target_key") == linked_key]
        return jsonify({
            "findings":       asset_findings,
            "linked_target":  linked_key,
            "total":          len(asset_findings),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/health", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_asset_health(asset_id: str):
    try:
        from nitesentinels.ham.health_engine import AssetHealthEngine
        from nitesentinels.ham.risk_engine   import AssetRiskEngine
        store  = _ham_store()
        org_id = _org_filter()
        asset  = store.get_asset(asset_id, org_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        # Get linked findings
        linked_key = asset.get("linked_target_key")
        findings = []
        if linked_key:
            try:
                _extract_findings = _get_extract_findings()
                findings = [f for f in _extract_findings() if f.get("target_key") == linked_key]
            except Exception:
                pass
        health = AssetHealthEngine().evaluate(asset, findings)
        risk   = AssetRiskEngine().evaluate(asset, findings)
        return jsonify({"health": health, "risk": risk, "asset_id": asset_id})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/qr", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_asset_qr(asset_id: str):
    """Return QR code PNG for the asset."""
    try:
        store  = _ham_store()
        org_id = _org_filter()
        asset  = store.get_asset(asset_id, org_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        qr_token = asset.get("qr_token")
        if not qr_token:
            return jsonify({"error": "No QR token for this asset"}), 400
        try:
            import qrcode  # type: ignore
            qr_url = f"{request.url_root.rstrip('/')}/api/ham/public/asset/{qr_token}"
            img = qrcode.make(qr_url)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            return send_file(buf, mimetype="image/png",
                             download_name=f"asset-{asset.get('asset_tag', asset_id)}.png")
        except ImportError:
            # Return SVG placeholder if qrcode not installed
            svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
            <rect width="200" height="200" fill="#0a1122"/>
            <text x="100" y="100" font-family="monospace" font-size="10" fill="#00d4ff"
                  text-anchor="middle" dominant-baseline="middle">
              QR: install qrcode[pil]
            </text></svg>"""
            return Response(svg, mimetype="image/svg+xml")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/assign", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.assign")
@secure_post
def api_ham_assign_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        data   = request.get_json() or {}
        actor  = _current_user()
        to_user = (data.get("assigned_to") or "").strip()
        if not to_user:
            return jsonify({"error": "assigned_to is required"}), 400
        ok = store.assign_asset(
            asset_id, org_id, to_user,
            data.get("assigned_to_email"),
            actor,
            reason=data.get("reason", ""),
            to_location=data.get("location"),
        )
        if not ok:
            return jsonify({"error": "Asset not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/transfer", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.transfer")
@secure_post
def api_ham_transfer_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        data   = request.get_json() or {}
        actor  = _current_user()
        to_user = (data.get("to_user") or "").strip()
        if not to_user:
            return jsonify({"error": "to_user is required"}), 400
        ok = store.assign_asset(
            asset_id, org_id, to_user,
            data.get("to_email"),
            actor,
            reason=data.get("reason", "Transfer"),
            to_location=data.get("to_location"),
        )
        if not ok:
            return jsonify({"error": "Asset not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/lifecycle", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.edit")
@secure_post
def api_ham_lifecycle_asset(asset_id: str):
    try:
        store      = _ham_store()
        org_id     = _org_filter()
        data       = request.get_json() or {}
        actor      = _current_user()
        new_status = (data.get("lifecycle_status") or data.get("status") or data.get("new_status") or "").strip()
        if not new_status:
            return jsonify({"error": "lifecycle_status is required"}), 400
        ok, msg = store.transition_lifecycle(asset_id, org_id, new_status, actor, data.get("notes", ""))
        if not ok:
            return jsonify({"error": msg}), 400
        return jsonify({"ok": True, "new_status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/retire", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.retire")
@secure_post
def api_ham_retire_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        actor  = _current_user()
        data   = request.get_json() or {}
        ok, msg = store.transition_lifecycle(asset_id, org_id, "retired", actor, data.get("reason", "Retirement"))
        if not ok:
            return jsonify({"error": msg}), 400
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/<asset_id>/dispose", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.dispose")
@secure_post
def api_ham_dispose_asset(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        actor  = _current_user()
        data   = request.get_json() or {}
        ok, msg = store.transition_lifecycle(asset_id, org_id, "disposed", actor, data.get("reason", "Disposal"))
        if ok:
            store.update_asset(asset_id, org_id, {
                "disposal_method": data.get("disposal_method"),
                "disposal_notes":  data.get("notes"),
            }, actor)
        else:
            return jsonify({"error": msg}), 400
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Custody log
# ===========================================================================

@ham_bp.route("/api/ham/assets/<asset_id>/custody", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_asset_custody(asset_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        log    = store.get_custody_log(asset_id, org_id)
        return jsonify({"items": log, "total": len(log)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Export / Import
# ===========================================================================

@ham_bp.route("/api/ham/assets/export/csv", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.export")
def api_ham_export_csv():
    try:
        store  = _ham_store()
        org_id = _org_filter()
        csv_data = store.export_csv(org_id)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=ham_assets.csv"},
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/assets/import/csv", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.create")
@secure_post
def api_ham_import_csv():
    try:
        store  = _ham_store()
        org_id = session.get("org_id") or "global"
        actor  = _current_user()
        f = request.files.get("file")
        if f:
            csv_content = f.read().decode("utf-8-sig")
        else:
            csv_content = (request.get_json() or {}).get("csv", "")
        if not csv_content.strip():
            return jsonify({"error": "No CSV data provided"}), 400
        result = store.import_csv(org_id, csv_content, actor)
        return jsonify({"ok": True, **result})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Bulk operations
# ===========================================================================

@ham_bp.route("/api/ham/assets/bulk", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.edit")
@secure_post
def api_ham_bulk():
    try:
        store     = _ham_store()
        org_id    = _org_filter()
        actor     = _current_user()
        data      = request.get_json() or {}
        asset_ids = data.get("asset_ids") or []
        action    = (data.get("action") or "").lower().strip()
        if not asset_ids or not isinstance(asset_ids, list):
            return jsonify({"error": "asset_ids list required"}), 400
        if action == "update":
            result = store.bulk_update(org_id, asset_ids, data.get("update", {}), actor)
        elif action == "lifecycle":
            new_status = data.get("lifecycle_status") or data.get("status", "")
            result = store.bulk_lifecycle(org_id, asset_ids, new_status, actor, data.get("notes", ""))
        elif action == "assign":
            to_user = data.get("assigned_to", "")
            result  = {"updated": 0, "failed": 0, "total": len(asset_ids)}
            for aid in asset_ids:
                ok = store.assign_asset(aid, org_id, to_user, None, actor, reason="Bulk assign")
                if ok:
                    result["updated"] += 1
                else:
                    result["failed"] += 1
        elif action == "delete":
            if not _has_permission("ham.assets.delete"):
                return jsonify({"error": "Forbidden"}), 403
            result = {"updated": 0, "failed": 0}
            for aid in asset_ids:
                if store.soft_delete_asset(aid, org_id, actor):
                    result["updated"] += 1
                else:
                    result["failed"] += 1
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400
        return jsonify({"ok": True, **result})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Discovery
# ===========================================================================

@ham_bp.route("/api/ham/discovery/jobs", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_list_discovery_jobs():
    try:
        store  = _ham_store()
        org_id = _org_filter()
        jobs   = store.list_discovery_jobs(org_id)
        return jsonify({"items": jobs, "total": len(jobs)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/discovery/start", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.create")
@secure_post
def api_ham_start_discovery():
    try:
        store        = _ham_store()
        org_id       = session.get("org_id") or "global"
        actor        = _current_user()
        data         = request.get_json() or {}
        target_range = (data.get("target_range") or data.get("target") or "").strip()
        scan_type    = (data.get("scan_type") or "ping").strip().lower()
        if not target_range:
            return jsonify({"error": "target_range is required"}), 400
        # Basic input safety: no shell metacharacters
        forbidden = set(";|&`$(){}\\<>!")
        if any(c in forbidden for c in target_range):
            return jsonify({"error": "Invalid characters in target_range"}), 400
        job_id = store.create_discovery_job(org_id, target_range, scan_type, actor)
        # Run discovery in background thread
        t = threading.Thread(
            target=_run_discovery_job,
            args=(job_id, org_id, target_range, scan_type, data),
            daemon=True,
        )
        t.start()
        return jsonify({"ok": True, "job_id": job_id, "status": "running"})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/discovery/jobs/<job_id>", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_get_discovery_job(job_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        job    = store.get_discovery_job(job_id, org_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/discovery/approve/<device_id>", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.create")
@secure_post
def api_ham_approve_device(device_id: str):
    try:
        store    = _ham_store()
        org_id   = session.get("org_id") or "global"
        actor    = _current_user()
        data     = request.get_json() or {}
        asset_id = store.approve_discovered_device(device_id, org_id, actor, data)
        return jsonify({"ok": True, "asset_id": asset_id})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/discovery/reject/<device_id>", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.create")
@secure_post
def api_ham_reject_device(device_id: str):
    try:
        store = _ham_store()
        actor = _current_user()
        ok    = store.reject_discovered_device(device_id, actor)
        if not ok:
            return jsonify({"error": "Device not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _run_discovery_job(job_id: str, org_id: str, target_range: str, scan_type: str, opts: dict) -> None:
    """Background thread: agentless network discovery using existing scanner."""
    from nitesentinels.web.ham_store import HAMStore
    import os
    db_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data", "llm_audit.db"
    )
    store = HAMStore(db_path)
    try:
        devices = _discover_network(target_range, scan_type, opts)
        store.complete_discovery_job(job_id, devices)
    except Exception as exc:
        store.fail_discovery_job(job_id, str(exc))


def _discover_network(target_range: str, scan_type: str, opts: dict) -> list[dict]:
    """Agentless device discovery via existing port scanner / ping."""
    import ipaddress, socket, subprocess, sys
    results = []
    # Expand CIDR or single IP
    try:
        network = ipaddress.ip_network(target_range, strict=False)
        hosts   = list(network.hosts()) if network.num_addresses <= 256 else []
    except ValueError:
        # Single hostname
        try:
            ip = socket.gethostbyname(target_range)
            hosts = [ipaddress.ip_address(ip)]
        except Exception:
            hosts = []

    for host_ip in hosts[:128]:  # Safety cap
        ip_str = str(host_ip)
        dev: dict = {"ip": ip_str}
        # Ping check
        try:
            if sys.platform == "win32":
                ret = subprocess.run(
                    ["ping", "-n", "1", "-w", "300", ip_str],
                    capture_output=True, timeout=3
                )
            else:
                ret = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip_str],
                    capture_output=True, timeout=3
                )
            if ret.returncode != 0:
                continue  # Host not reachable
        except Exception:
            continue

        # Hostname lookup
        try:
            dev["hostname"] = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            dev["hostname"] = ip_str

        # Quick port scan (top ports)
        if scan_type in ("ports", "full"):
            open_ports = []
            for port in [22, 80, 135, 139, 443, 445, 3389, 8080]:
                try:
                    s = socket.socket()
                    s.settimeout(0.3)
                    if s.connect_ex((ip_str, port)) == 0:
                        open_ports.append(port)
                    s.close()
                except Exception:
                    pass
            dev["open_ports"] = open_ports
            # OS guess from ports
            if 3389 in open_ports or 135 in open_ports:
                dev["os_guess"] = "Windows"
            elif 22 in open_ports:
                dev["os_guess"] = "Linux/Unix"
            else:
                dev["os_guess"] = "Unknown"

        results.append(dev)

    return results


# ===========================================================================
# API — Agents
# ===========================================================================

@ham_bp.route("/api/ham/agents", methods=["GET"])
@login_required
@require_ham_perm("ham.agents.manage")
def api_ham_list_agents():
    try:
        store  = _ham_store()
        org_id = _org_filter()
        agents = store.list_agents(org_id)
        return jsonify({"items": agents, "total": len(agents)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/agents/enroll", methods=["POST"])
@login_required
@require_ham_perm("ham.agents.manage")
@secure_post
def api_ham_enroll_agent():
    try:
        store  = _ham_store()
        org_id = session.get("org_id") or "global"
        actor  = _current_user()
        result = store.create_agent_enrollment_token(org_id, actor)
        server_url = request.url_root.rstrip("/")
        install_win = (
            f"# Windows — run as Administrator\n"
            f"$env:HAM_SERVER='{server_url}'; $env:HAM_TOKEN='{result['raw_token']}'\n"
            f"python nitesentinel_agent.py"
        )
        install_lin = (
            f"# Linux — run as root\n"
            f"export HAM_SERVER='{server_url}' HAM_TOKEN='{result['raw_token']}'\n"
            f"python3 nitesentinel_agent.py"
        )
        return jsonify({
            "ok":           True,
            "token_id":     result["token_id"],
            "raw_token":    result["raw_token"],
            "token":        result["raw_token"],
            "expires_at":   result["expires_at"],
            "install_cmd_windows": install_win,
            "install_cmd_linux":   install_lin,
        })
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/agents/<agent_id>/revoke", methods=["POST"])
@login_required
@require_ham_perm("ham.agents.manage")
@secure_post
def api_ham_revoke_agent(agent_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        ok     = store.revoke_agent(agent_id, org_id)
        if not ok:
            return jsonify({"error": "Agent not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/agents/<agent_id>/rotate", methods=["POST"])
@login_required
@require_ham_perm("ham.agents.manage")
@secure_post
def api_ham_rotate_agent_token(agent_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        actor  = _current_user()
        result = store.rotate_agent_token(agent_id, org_id, actor)
        return jsonify({"ok": True, **result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/agents/<agent_id>", methods=["DELETE"])
@login_required
@require_ham_perm("ham.agents.manage")
@secure_post
def api_ham_delete_agent(agent_id: str):
    try:
        store  = _ham_store()
        org_id = _org_filter()
        ok     = store.delete_agent(agent_id, org_id)
        if not ok:
            return jsonify({"error": "Agent not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/agents/checkin", methods=["POST"])
def api_ham_agent_checkin():
    """Agent heartbeat endpoint. Uses bearer token auth (no Flask session)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    raw_token = auth[7:]
    try:
        store     = _ham_store()
        tok       = store.validate_agent_token(raw_token)
        if not tok:
            return jsonify({"error": "Invalid or expired token"}), 401
        agent_id  = tok.get("agent_id")
        telemetry = request.get_json() or {}

        # First check-in after enrollment — register the agent
        if not agent_id:
            hostname = telemetry.get("hostname", "unknown")
            platform = telemetry.get("platform", "unknown")
            version  = telemetry.get("agent_version", "1.0")
            agent_id = store.register_agent(tok["org_id"], tok["id"], hostname, platform, version)

        store.process_agent_checkin(agent_id, telemetry)
        return jsonify({"ok": True, "agent_id": agent_id})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Warranty
# ===========================================================================

@ham_bp.route("/api/ham/warranty", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_warranty():
    try:
        store      = _ham_store()
        org_id     = _org_filter()
        days_ahead = int(request.args.get("days", 90))
        report     = store.get_warranty_report(org_id, days_ahead)
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Reconciliation / Ghost assets
# ===========================================================================

@ham_bp.route("/api/ham/reconciliation", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_reconciliation():
    try:
        store       = _ham_store()
        org_id      = _org_filter()
        offline_days = int(request.args.get("offline_days", 30))
        ghosts      = store.get_ghost_assets(org_id, offline_days)
        return jsonify({
            "ghost_assets":  ghosts,
            "total":         len(ghosts),
            "offline_days":  offline_days,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Health summary
# ===========================================================================

@ham_bp.route("/api/ham/health/summary", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.view")
def api_ham_health_summary():
    try:
        store  = _ham_store()
        org_id = _org_filter()
        kpis   = store.get_dashboard_kpis(org_id)
        return jsonify({
            "healthy":  kpis.get("health_healthy", 0),
            "warning":  kpis.get("health_warning", 0),
            "critical": kpis.get("health_critical", 0),
            "offline":  kpis.get("health_offline", 0),
            "total":    kpis.get("total", 0),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# API — Reports
# ===========================================================================

@ham_bp.route("/api/ham/reports/<report_type>", methods=["GET"])
@login_required
@require_ham_perm("ham.reports.view")
def api_ham_report(report_type: str):
    try:
        store   = _ham_store()
        org_id  = _org_filter()
        fmt     = request.args.get("format", "json").lower()
        report  = _build_ham_report(store, org_id, report_type)
        if "error" in report:
            return jsonify(report), 400
        if fmt == "csv" and report_type == "inventory":
            csv_data = store.export_csv(org_id)
            return Response(
                csv_data, mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=ham_{report_type}.csv"},
            )
        if fmt == "html":
            html = _render_ham_report_html(report, report_type)
            return Response(
                html, mimetype="text/html",
                headers={"Content-Disposition": f"attachment; filename=ham_{report_type}_report.html"},
            )
        return jsonify(report)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


def _build_ham_report(store, org_id: str | None, report_type: str) -> dict:
    now = datetime.utcnow().isoformat()
    if report_type == "inventory":
        data = store.list_assets(org_id, page_size=10000, include_retired=True)
        kpis = store.get_dashboard_kpis(org_id)
        return {
            "title":      "Hardware Asset Inventory Report",
            "type":       "inventory",
            "generated_at": now,
            "summary":    kpis,
            "assets":     data["items"],
            "total":      data["total"],
        }
    elif report_type == "warranty":
        rep = store.get_warranty_report(org_id)
        return {
            "title":      "Warranty Status Report",
            "type":       "warranty",
            "generated_at": now,
            **rep,
        }
    elif report_type == "lifecycle":
        kpis = store.get_dashboard_kpis(org_id)
        return {
            "title":      "Asset Lifecycle Report",
            "type":       "lifecycle",
            "generated_at": now,
            "by_lifecycle": kpis.get("by_lifecycle", {}),
            "total":      kpis.get("total", 0),
        }
    elif report_type == "reconciliation":
        ghosts = store.get_ghost_assets(org_id)
        return {
            "title":      "Ghost Asset Reconciliation Report",
            "type":       "reconciliation",
            "generated_at": now,
            "ghost_assets": ghosts,
            "total":      len(ghosts),
        }
    elif report_type == "risk":
        data = store.list_assets(org_id, page_size=10000, sort_by="risk", order="desc")
        return {
            "title":       "Asset Risk Report",
            "type":        "risk",
            "generated_at": now,
            "assets":      [a for a in data["items"] if (a.get("risk_level") or "low") in ("high", "critical")],
            "total":       data["total"],
        }
    return {"error": f"Unknown report type: {report_type}"}


def _render_ham_report_html(report: dict, report_type: str) -> str:
    title = report.get("title", "HAM Report")
    gen   = report.get("generated_at", "")
    rows  = ""
    assets: list[dict] = report.get("assets") or report.get("expiring") or []
    if assets:
        rows = "".join(
            f"<tr>"
            f"<td>{a.get('asset_tag','—')}</td>"
            f"<td>{a.get('name','')}</td>"
            f"<td>{a.get('asset_type','')}</td>"
            f"<td>{a.get('assigned_to','—')}</td>"
            f"<td>{a.get('lifecycle_status','')}</td>"
            f"<td>{a.get('health_status','')}</td>"
            f"<td>{a.get('risk_level','low')}</td>"
            f"<td>{a.get('warranty_end','—')}</td>"
            f"</tr>"
            for a in assets
        )
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:Arial,sans-serif;background:#071124;color:#e8f0ff;margin:40px}}
h1{{color:#49d1ff}}h2{{color:#cbd5e1;margin-top:24px}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{border:1px solid rgba(255,255,255,0.1);padding:10px;text-align:left;font-size:13px}}
th{{background:rgba(0,212,255,0.1);color:#9fb8d4;font-weight:700}}
tr:nth-child(even){{background:rgba(255,255,255,0.03)}}
.brand{{font-size:22px;font-weight:800;color:#49d1ff;margin-bottom:8px}}
</style></head><body>
<div class="brand">NiteSentinel — Hardware Asset Management</div>
<h1>{title}</h1>
<p style="color:#8ea7cb">Generated: {gen}</p>
<table>
<tr><th>Asset Tag</th><th>Name</th><th>Type</th><th>Assigned To</th>
<th>Lifecycle</th><th>Health</th><th>Risk</th><th>Warranty End</th></tr>
{rows or '<tr><td colspan="8" style="text-align:center;color:#8ea7cb">No assets found</td></tr>'}
</table>
</body></html>"""


# ===========================================================================
# API — Audit campaigns
# ===========================================================================

@ham_bp.route("/api/ham/audit/campaigns", methods=["GET"])
@login_required
@require_ham_perm("ham.assets.audit")
def api_ham_list_campaigns():
    try:
        store    = _ham_store()
        org_id   = _org_filter()
        campaigns = store.list_audit_campaigns(org_id)
        return jsonify({"items": campaigns, "total": len(campaigns)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/audit/campaigns", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.audit")
@secure_post
def api_ham_create_campaign():
    try:
        store   = _ham_store()
        org_id  = session.get("org_id") or "global"
        actor   = _current_user()
        data    = request.get_json() or {}
        name    = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Campaign name is required"}), 400
        cid = store.create_audit_campaign(org_id, name, data, actor)
        return jsonify({"ok": True, "campaign_id": cid}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@ham_bp.route("/api/ham/audit/campaigns/<campaign_id>/result", methods=["POST"])
@login_required
@require_ham_perm("ham.assets.audit")
@secure_post
def api_ham_submit_audit_result(campaign_id: str):
    try:
        store  = _ham_store()
        org_id = session.get("org_id") or "global"
        actor  = _current_user()
        data   = request.get_json() or {}
        asset_id = data.get("asset_id")
        if not asset_id:
            return jsonify({"error": "asset_id is required"}), 400
        rid = store.submit_audit_result(campaign_id, asset_id, org_id, actor, data)
        return jsonify({"ok": True, "result_id": rid})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ===========================================================================
# Internal helper — recompute health + risk and persist to asset
# ===========================================================================

def _recompute_health_risk(store, asset_id: str, org_id: str | None, actor: str) -> None:
    """Compute and persist health + risk scores for the given asset."""
    try:
        from nitesentinels.ham.health_engine import AssetHealthEngine
        from nitesentinels.ham.risk_engine   import AssetRiskEngine
        asset = store.get_asset(asset_id, org_id)
        if not asset:
            return
        linked = asset.get("linked_target_key")
        findings = []
        if linked:
            try:
                _extract_findings = _get_extract_findings()
                findings = [f for f in _extract_findings() if f.get("target_key") == linked]
            except Exception:
                pass
        health = AssetHealthEngine().evaluate(asset, findings)
        risk   = AssetRiskEngine().evaluate(asset, findings)
        store.update_asset(asset_id, org_id, {
            "health_status":    health["health_status"],
            "risk_level":       risk["risk_level"],
            "risk_score":       risk["risk_score"],
            "last_health_check": datetime.utcnow().isoformat(),
        }, actor)
    except Exception as exc:
        pass  # Health recompute is best-effort
