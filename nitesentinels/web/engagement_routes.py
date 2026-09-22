"""
NiteSentinel Engagement Routes Blueprint
=========================================
Flask Blueprint providing all REST API and page routes for the
professional assessment lifecycle.

Routes:

    Pages (rendered templates):
        GET  /clients                       → clients.html
        GET  /clients/<id>                  → client_profile.html
        GET  /engagements                   → engagements.html
        GET  /engagements/<id>              → engagement_overview.html (central workspace)
        GET  /engagements/<id>/scope        → engagement_scope.html
        GET  /engagements/<id>/assets       → engagement_assets.html
        GET  /engagements/<id>/section/<s>  → section-specific template
        GET  /engagements/<id>/findings     → engagement_findings.html
        GET  /engagements/<id>/evidence     → engagement_evidence.html
        GET  /engagements/<id>/dlp          → engagement_dlp.html
        GET  /engagements/<id>/risk-register → risk_register.html
        GET  /engagements/<id>/remediation  → engagement_remediation.html
        GET  /engagements/<id>/retest       → engagement_retest.html
        GET  /engagements/<id>/reports      → engagement_reports.html
        GET  /engagements/<id>/compliance   → engagement_compliance.html

    REST API:
        /api/clients/...                    → Client CRUD
        /api/engagements/...                → Engagement CRUD + state
        /api/engagements/<id>/scope/...     → Scope management
        /api/engagements/<id>/assets/...    → Asset management
        /api/engagements/<id>/responses/... → Assessment responses
        /api/engagements/<id>/findings/...  → Finding lifecycle
        /api/engagements/<id>/evidence/...  → Evidence upload/download
        /api/engagements/<id>/dlp/...       → DLP 4-layer model
        /api/engagements/<id>/risk/...      → Risk register
        /api/engagements/<id>/remediation/...→ Remediation
        /api/engagements/<id>/retests/...   → Retest
        /api/engagements/<id>/reports/...   → Report generation
        /api/engagements/<id>/overview      → Full dashboard data

NiteSentinel v2.0 — NITECHSPARK MSME Cybersecurity Assessment Platform
"""

from __future__ import annotations

import json
import os
from functools import wraps

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from nitesentinels.web.engagement_store import (
    ASSESSMENT_SECTIONS,
    ENGAGEMENT_STATES,
    FINDING_STATUSES,
    RESPONSE_STATUSES,
    EngagementStore,
    get_store,
)
from nitesentinels.web.assessment_service import AssessmentService

# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------

engagement_bp = Blueprint(
    "engagements",
    __name__,
    url_prefix="",
)

# ---------------------------------------------------------------------------
# Lazy service accessor (avoids circular import with app.py)
# ---------------------------------------------------------------------------

_svc: AssessmentService | None = None


def _get_svc() -> AssessmentService:
    global _svc
    if _svc is None:
        _svc = AssessmentService(get_store())
    return _svc


def _store() -> EngagementStore:
    return _get_svc().store


# ---------------------------------------------------------------------------
# Auth helpers (re-use app.py decorators via late import)
# ---------------------------------------------------------------------------

def _login_required_wrapper(f):
    """Thin wrapper that defers to app.py's login_required at call time."""
    @wraps(f)
    def inner(*args, **kwargs):
        from nitesentinels.web.app import login_required
        return login_required(f)(*args, **kwargs)
    return inner


def _require_permission_wrapper(permission: str):
    def decorator(f):
        @wraps(f)
        def inner(*args, **kwargs):
            from nitesentinels.web.app import has_permission
            org_id = session.get("org_id")
            if not has_permission(org_id, permission):
                return jsonify({"error": f"Permission denied: {permission}"}), 403
            return f(*args, **kwargs)
        return inner
    return decorator


def _csrf_ok() -> bool:
    """Validate CSRF token on mutating requests."""
    from flask import current_app
    if current_app.config.get("TESTING"):
        return True
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    return bool(token and token == session.get("csrf_token"))


def _actor() -> str:
    return session.get("username") or "anonymous"


def _org_id() -> str | None:
    return session.get("org_id")


def _csrf_token():
    from nitesentinels.web.app import _csrf_token as app_csrf
    return app_csrf()


def _render(template: str, **kwargs):
    """Render with common context variables."""
    return render_template(
        template,
        username=session.get("username", "operator"),
        role=session.get("role", "viewer"),
        csrf_token=_csrf_token(),
        **kwargs,
    )


def _audit(action: str, *, engagement_id: str | None = None, object_type: str | None = None,
           object_id: str | None = None, result: str = "SUCCESS", details: dict | None = None):
    _store().audit(
        _actor(), action,
        engagement_id=engagement_id,
        object_type=object_type,
        object_id=object_id,
        result=result,
        details=details,
        ip_address=request.remote_addr,
    )


# ---------------------------------------------------------------------------
# Page Routes — Client
# ---------------------------------------------------------------------------

@engagement_bp.route("/clients")
@_login_required_wrapper
def clients_page():
    return _render("clients.html")


@engagement_bp.route("/clients/<client_id>")
@_login_required_wrapper
def client_profile_page(client_id: str):
    client = _store().get_client(client_id)
    if not client:
        return _render("404.html"), 404
    return _render("client_profile.html", client=client)


# ---------------------------------------------------------------------------
# Page Routes — Engagements
# ---------------------------------------------------------------------------

@engagement_bp.route("/engagements")
@_login_required_wrapper
def engagements_page():
    return _render("engagements.html")


@engagement_bp.route("/engagements/<engagement_id>")
@_login_required_wrapper
def engagement_overview_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_overview.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/scope")
@_login_required_wrapper
def engagement_scope_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_scope.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/assets")
@_login_required_wrapper
def engagement_assets_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_assets.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/iam")
@_login_required_wrapper
def engagement_iam_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_iam.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/backup")
@_login_required_wrapper
def engagement_backup_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_backup.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/network")
@_login_required_wrapper
def engagement_network_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_network.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/servers")
@_login_required_wrapper
def engagement_servers_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_servers.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/endpoints")
@_login_required_wrapper
def engagement_endpoints_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_endpoints.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/web")
@_login_required_wrapper
def engagement_web_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_web.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/section/<section_name>")
@_login_required_wrapper
def engagement_section_dynamic_page(engagement_id: str, section_name: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    sec_lower = section_name.lower()
    template_map = {
        "iam": "engagement_iam.html",
        "backup": "engagement_backup.html",
        "network": "engagement_network.html",
        "servers": "engagement_servers.html",
        "endpoints": "engagement_endpoints.html",
        "web": "engagement_web.html",
        "dlp": "engagement_dlp.html",
    }
    tmpl = template_map.get(sec_lower, "engagement_section_base.html")
    return _render(tmpl, engagement=eng, engagement_id=engagement_id, section_name=section_name.upper())



@engagement_bp.route("/engagements/<engagement_id>/dlp")
@_login_required_wrapper
def engagement_dlp_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_dlp.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/findings")
@_login_required_wrapper
def engagement_findings_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_findings.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/evidence")
@_login_required_wrapper
def engagement_evidence_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_evidence.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/risk-register")
@_login_required_wrapper
def engagement_risk_register_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("risk_register.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/remediation")
@_login_required_wrapper
def engagement_remediation_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_remediation.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/retest")
@_login_required_wrapper
def engagement_retest_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_retest.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/reports")
@_login_required_wrapper
def engagement_reports_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_reports.html", engagement=eng, engagement_id=engagement_id)


@engagement_bp.route("/engagements/<engagement_id>/compliance")
@_login_required_wrapper
def engagement_compliance_page(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return _render("404.html"), 404
    return _render("engagement_compliance.html", engagement=eng, engagement_id=engagement_id)


# ---------------------------------------------------------------------------
# REST API — Clients
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/clients", methods=["GET"])
@_login_required_wrapper
def api_list_clients():
    clients = _store().list_clients()
    return jsonify({"clients": clients, "total": len(clients)})


@engagement_bp.route("/api/clients", methods=["POST"])
@_login_required_wrapper
def api_create_client():
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    try:
        cid, client = _get_svc().create_client(data, actor=_actor())
        return jsonify({"client_id": cid, "client": client}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/clients/<client_id>", methods=["GET"])
@_login_required_wrapper
def api_get_client(client_id: str):
    client = _store().get_client(client_id)
    if not client:
        return jsonify({"error": "Client not found"}), 404
    engagements = _store().list_engagements(client_id=client_id)
    return jsonify({"client": client, "engagements": engagements})


@engagement_bp.route("/api/clients/<client_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_client(client_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_client(client_id, data, actor=_actor())
    if ok:
        _audit("UPDATE_CLIENT", object_type="CLIENT", object_id=client_id)
        return jsonify({"ok": True, "client": _store().get_client(client_id)})
    return jsonify({"error": "Not found or nothing to update"}), 404


@engagement_bp.route("/api/clients/<client_id>", methods=["DELETE"])
@_login_required_wrapper
def api_delete_client(client_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_client(client_id)
    if ok:
        _audit("DELETE_CLIENT", object_type="CLIENT", object_id=client_id)
        return jsonify({"ok": True})
    return jsonify({"error": "Client not found"}), 404


# ---------------------------------------------------------------------------
# REST API — Engagements
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements", methods=["GET"])
@_login_required_wrapper
def api_list_engagements():
    client_id = request.args.get("client_id")
    status = request.args.get("status")
    engagements = _store().list_engagements(client_id=client_id, status=status, org_id=_org_id())
    return jsonify({"engagements": engagements, "total": len(engagements)})


@engagement_bp.route("/api/engagements", methods=["POST"])
@_login_required_wrapper
def api_create_engagement():
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    client_id = (data.get("client_id") or "").strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
    try:
        eid, eng = _get_svc().create_engagement(client_id, data, actor=_actor())
        return jsonify({"engagement_id": eid, "engagement": eng}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/engagements/<engagement_id>", methods=["GET"])
@_login_required_wrapper
def api_get_engagement(engagement_id: str):
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return jsonify({"error": "Engagement not found"}), 404
    return jsonify({"engagement": eng})


@engagement_bp.route("/api/engagements/<engagement_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_engagement(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_engagement(engagement_id, data)
    if ok:
        _audit("UPDATE_ENGAGEMENT", engagement_id=engagement_id, object_type="ENGAGEMENT", object_id=engagement_id)
        return jsonify({"ok": True, "engagement": _store().get_engagement(engagement_id)})
    return jsonify({"error": "Not found or invalid update"}), 404


@engagement_bp.route("/api/engagements/<engagement_id>/authorize", methods=["POST"])
@_login_required_wrapper
def api_authorize_engagement(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    doc = (data.get("authorization_document") or "").strip()
    if not doc:
        return jsonify({"error": "authorization_document is required"}), 400
    ok, msg = _get_svc().authorize_engagement(
        engagement_id, doc, data.get("authorized_by", _actor()), actor=_actor()
    )
    return jsonify({"ok": ok, "message": msg})


@engagement_bp.route("/api/engagements/<engagement_id>/status", methods=["POST"])
@_login_required_wrapper
def api_advance_engagement_status(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    new_status = (data.get("status") or "").strip().upper()
    ok, msg = _store().advance_engagement_status(engagement_id, new_status, actor=_actor())
    if ok:
        return jsonify({"ok": True, "status": new_status, "message": msg})
    return jsonify({"ok": False, "error": msg}), 400


@engagement_bp.route("/api/engagements/<engagement_id>/overview", methods=["GET"])
@_login_required_wrapper
def api_engagement_overview(engagement_id: str):
    try:
        data = _get_svc().get_engagement_dashboard(engagement_id)
        if "error" in data:
            return jsonify(data), 404
        progress = _get_svc().get_full_progress(engagement_id)
        data["progress"] = progress
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/engagements/<engagement_id>", methods=["DELETE"])
@_login_required_wrapper
def api_delete_engagement(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_engagement(engagement_id)
    if ok:
        _audit("DELETE_ENGAGEMENT", engagement_id=engagement_id, object_type="ENGAGEMENT", object_id=engagement_id)
        return jsonify({"ok": True})
    return jsonify({"error": "Engagement not found"}), 404


# ---------------------------------------------------------------------------
# REST API — Scope
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/scope", methods=["GET"])
@_login_required_wrapper
def api_list_scope(engagement_id: str):
    return jsonify({"scope": _store().list_scope(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/scope", methods=["POST"])
@_login_required_wrapper
def api_add_scope(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    scope_type = (data.get("scope_type") or "").strip().upper()
    value = (data.get("value") or "").strip()
    if not scope_type or not value:
        return jsonify({"error": "scope_type and value are required"}), 400
    sid = _store().add_scope_entry(
        engagement_id, scope_type, value,
        description=data.get("description"),
        excluded=bool(data.get("excluded", False)),
    )
    _audit("ADD_SCOPE", engagement_id=engagement_id, object_type="SCOPE", object_id=sid,
           details={"scope_type": scope_type, "value": value})
    return jsonify({"scope_id": sid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/scope/<scope_id>", methods=["DELETE"])
@_login_required_wrapper
def api_delete_scope(engagement_id: str, scope_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_scope_entry(scope_id)
    if ok:
        _audit("DELETE_SCOPE", engagement_id=engagement_id, object_type="SCOPE", object_id=scope_id)
        return jsonify({"ok": True})
    return jsonify({"error": "Scope entry not found"}), 404


@engagement_bp.route("/api/engagements/<engagement_id>/scope/validate", methods=["POST"])
@_login_required_wrapper
def api_validate_scope(engagement_id: str):
    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    ok, reason = _store().validate_scope(engagement_id)
    in_scope = _store().is_target_in_scope(engagement_id, target) if target else None
    return jsonify({"authorized": ok, "reason": reason, "target_in_scope": in_scope, "in_scope": in_scope, "target": target})


# ---------------------------------------------------------------------------
# REST API — Assets
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/assets", methods=["GET"])
@_login_required_wrapper
def api_list_assets(engagement_id: str):
    return jsonify({"assets": _store().list_assets(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/assets", methods=["POST"])
@_login_required_wrapper
def api_add_asset(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    aid = _store().add_asset(
        engagement_id,
        asset_id=data.get("asset_id"),
        asset_type=data.get("asset_type"),
        hostname=data.get("hostname"),
        ip_address=data.get("ip_address"),
        os=data.get("os"),
        criticality=data.get("criticality", "MEDIUM"),
        data_sensitivity=data.get("data_sensitivity", "INTERNAL"),
        include_in_assessment=data.get("include_in_assessment", True),
        assessment_notes=data.get("assessment_notes"),
    )
    _audit("ADD_ASSET", engagement_id=engagement_id, object_type="ASSET", object_id=aid,
           details={"hostname": data.get("hostname"), "ip": data.get("ip_address")})
    return jsonify({"asset_id": aid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/assets/<asset_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_asset(engagement_id: str, asset_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_asset(asset_id, data)
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/assets/<asset_id>", methods=["DELETE"])
@_login_required_wrapper
def api_delete_asset(engagement_id: str, asset_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_asset(asset_id)
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Assessment Questions
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/questions", methods=["GET"])
@_login_required_wrapper
def api_list_questions():
    section = request.args.get("section")
    questions = _store().list_questions(section=section)
    return jsonify({"questions": questions, "total": len(questions)})


# ---------------------------------------------------------------------------
# REST API — Assessment Responses
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/responses", methods=["GET"])
@_login_required_wrapper
def api_list_responses(engagement_id: str):
    section = request.args.get("section")
    responses = _store().list_responses(engagement_id, section=section)
    return jsonify({"responses": responses, "total": len(responses)})


@engagement_bp.route("/api/engagements/<engagement_id>/responses/<question_id>", methods=["GET"])
@_login_required_wrapper
def api_get_response(engagement_id: str, question_id: str):
    resp = _store().get_or_create_response(engagement_id, question_id)
    return jsonify({"response": resp})


@engagement_bp.route("/api/engagements/<engagement_id>/responses/<question_id>", methods=["POST", "PUT"])
@_login_required_wrapper
def api_update_response(engagement_id: str, question_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    try:
        result = _get_svc().update_response_and_create_finding(
            engagement_id, question_id, data, actor=_actor()
        )
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/engagements/<engagement_id>/section-status", methods=["GET"])
@_login_required_wrapper
def api_section_status(engagement_id: str):
    section = request.args.get("section")
    if section:
        return jsonify(_store().get_section_status(engagement_id, section.upper()))
    result = {s: _store().get_section_status(engagement_id, s) for s in ASSESSMENT_SECTIONS}
    return jsonify({"sections": result})


# ---------------------------------------------------------------------------
# REST API — Findings
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/findings", methods=["GET"])
@_login_required_wrapper
def api_list_findings(engagement_id: str):
    section = request.args.get("section")
    severity = request.args.get("severity")
    status = request.args.get("status")
    findings = _store().list_findings(engagement_id, section=section, severity=severity, status=status)
    return jsonify({"findings": findings, "total": len(findings)})


@engagement_bp.route("/api/engagements/<engagement_id>/findings", methods=["POST"])
@_login_required_wrapper
def api_create_finding(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    section = (data.get("section") or "GENERAL").strip().upper()
    severity = (data.get("severity") or "MEDIUM").strip().upper()
    if not title or not description:
        return jsonify({"error": "title and description are required"}), 400
    fid = _store().create_finding(
        engagement_id, section, title, description, severity,
        question_id=data.get("question_id"),
        category=data.get("category"),
        affected_asset=data.get("affected_asset"),
        likelihood=data.get("likelihood", "MEDIUM"),
        impact=data.get("impact", "MEDIUM"),
        asset_criticality=data.get("asset_criticality", "MEDIUM"),
        data_sensitivity=data.get("data_sensitivity", "INTERNAL"),
        existing_controls=data.get("existing_controls"),
        controls_mitigate=bool(data.get("controls_mitigate", False)),
        business_impact=data.get("business_impact"),
        technical_impact=data.get("technical_impact"),
        recommendation=data.get("recommendation"),
        remediation_guidance=data.get("remediation_guidance"),
        retest_requirement=data.get("retest_requirement"),
        reference=data.get("reference"),
        framework_refs=data.get("framework_refs"),
        owner=data.get("owner"),
        due_date=data.get("due_date"),
        created_by=_actor(),
    )
    # Auto sync to risk register
    _store().sync_findings_to_risk_register(engagement_id)
    _audit("CREATE_FINDING", engagement_id=engagement_id, object_type="FINDING", object_id=fid,
           details={"title": title, "severity": severity})
    return jsonify({"finding_id": fid, "finding": _store().get_finding(fid)}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/findings/<finding_id>", methods=["GET"])
@_login_required_wrapper
def api_get_finding(engagement_id: str, finding_id: str):
    f = _store().get_finding(finding_id)
    if not f or f.get("engagement_id") != engagement_id:
        return jsonify({"error": "Finding not found"}), 404
    evidence = _store().list_evidence(engagement_id, finding_id=finding_id)
    remediation = _store().list_remediation_actions(finding_id=finding_id)
    retests = _store().list_retests(engagement_id)
    retests = [r for r in retests if r.get("finding_id") == finding_id]
    return jsonify({"finding": f, "evidence": evidence, "remediation": remediation, "retests": retests})


@engagement_bp.route("/api/engagements/<engagement_id>/findings/<finding_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_finding(engagement_id: str, finding_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_finding(finding_id, data, actor=_actor())
    if ok:
        _store().sync_findings_to_risk_register(engagement_id)
        _audit("UPDATE_FINDING", engagement_id=engagement_id, object_type="FINDING", object_id=finding_id,
               details={"changes": list(data.keys())})
        return jsonify({"ok": True, "finding": _store().get_finding(finding_id)})
    return jsonify({"error": "Not found or invalid update"}), 404


@engagement_bp.route("/api/engagements/<engagement_id>/findings/<finding_id>/accept-risk", methods=["POST"])
@_login_required_wrapper
def api_accept_risk(engagement_id: str, finding_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    justification = (data.get("justification") or "").strip()
    if not justification:
        return jsonify({"error": "justification is required for risk acceptance"}), 400
    ok = _store().update_finding(finding_id, {
        "status": "RISK_ACCEPTED",
        "risk_priority_override": "ACCEPTED",
        "risk_override_justification": justification,
    }, actor=_actor())
    if ok:
        _audit("ACCEPT_RISK", engagement_id=engagement_id, object_type="FINDING", object_id=finding_id,
               details={"justification": justification})
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/findings/import-scan", methods=["POST"])
@_login_required_wrapper
def api_import_scan_findings(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    scan_key = data.get("scan_key")
    section = data.get("section", "VULNERABILITY_ASSESSMENT")
    # Load scan result from existing stored_scan_results
    try:
        from nitesentinels.web.app import stored_scan_results
        scan_result = stored_scan_results.get(scan_key)
    except ImportError:
        scan_result = None
    if not scan_result:
        return jsonify({"error": "Scan result not found. Run a scan first."}), 404
    # Scope check
    target = scan_result.get("hostname") or scan_key
    ok, reason = _get_svc().authorize_scan(engagement_id, target, actor=_actor())
    if not ok:
        return jsonify({"error": reason, "scope_blocked": True}), 403
    imported = _get_svc().import_scan_results(engagement_id, scan_result, section=section, actor=_actor())
    return jsonify({"imported": len(imported), "finding_ids": imported})


# ---------------------------------------------------------------------------
# REST API — Evidence
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/evidence", methods=["GET"])
@_login_required_wrapper
def api_list_evidence(engagement_id: str):
    finding_id = request.args.get("finding_id")
    question_id = request.args.get("question_id")
    evidence = _store().list_evidence(engagement_id, finding_id=finding_id, question_id=question_id)
    return jsonify({"evidence": evidence, "total": len(evidence)})


@engagement_bp.route("/api/engagements/<engagement_id>/evidence", methods=["POST"])
@engagement_bp.route("/api/engagements/<engagement_id>/evidence/upload", methods=["POST"])
@_login_required_wrapper
def api_upload_evidence(engagement_id: str):
    # Handle both multipart file uploads and JSON metadata-only records
    svc = _get_svc()
    json_data = request.get_json(silent=True) or {}
    finding_id = request.form.get("finding_id") or json_data.get("finding_id")
    question_id = request.form.get("question_id") or json_data.get("question_id")
    description = request.form.get("description") or json_data.get("description") or ""
    sensitivity = (request.form.get("sensitivity") or json_data.get("sensitivity") or "CONFIDENTIAL").upper()
    evidence_type = (request.form.get("evidence_type") or json_data.get("evidence_type") or "OTHER").upper()
    notes = request.form.get("notes") or json_data.get("notes")

    if "file" in request.files:
        # File upload path
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "No file selected"}), 400
        try:
            eid, safe_name = svc.store_evidence_file(
                engagement_id, f.stream, f.filename, _actor(),
                finding_id=finding_id,
                question_id=question_id,
                description=description or f.filename,
                sensitivity=sensitivity,
                evidence_type=evidence_type,
                notes=notes,
            )
            return jsonify({
                "evidence_id": eid,
                "file_name": safe_name,
                "disclaimer": "File stored. NOTE: No malware scanning is performed on uploaded files.",
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        # Metadata-only evidence record (no file)
        data = request.get_json() or {}
        eid = _store().add_evidence(
            engagement_id,
            description=data.get("description", "Evidence record"),
            collected_by=_actor(),
            evidence_type=evidence_type,
            finding_id=finding_id,
            question_id=question_id,
            source=data.get("source"),
            sensitivity=sensitivity,
            notes=data.get("notes"),
        )
        _audit("ADD_EVIDENCE_RECORD", engagement_id=engagement_id, object_type="EVIDENCE", object_id=eid)
        return jsonify({"evidence_id": eid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/evidence/<evidence_id>/download", methods=["GET"])
@_login_required_wrapper
def api_download_evidence(engagement_id: str, evidence_id: str):
    svc = _get_svc()
    path, msg = svc.get_evidence_file_path(evidence_id, _actor(), engagement_id)
    if not path:
        return jsonify({"error": msg}), 403 if "denied" in msg.lower() else 404
    ev = _store().get_evidence(evidence_id)
    return send_file(
        path,
        as_attachment=True,
        download_name=ev.get("file_name") or os.path.basename(path),
    )


@engagement_bp.route("/api/engagements/<engagement_id>/evidence/<evidence_id>", methods=["DELETE"])
@_login_required_wrapper
def api_delete_evidence(engagement_id: str, evidence_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ev = _store().get_evidence(evidence_id)
    if not ev or ev.get("engagement_id") != engagement_id:
        return jsonify({"error": "Evidence not found"}), 404
    ok = _store().delete_evidence(evidence_id, soft=True)
    _audit("DELETE_EVIDENCE", engagement_id=engagement_id, object_type="EVIDENCE", object_id=evidence_id)
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — DLP
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/dlp/discovery", methods=["GET"])
@_login_required_wrapper
def api_dlp_discovery_list(engagement_id: str):
    return jsonify({"records": _store().list_dlp_data_records(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/discovery", methods=["POST"])
@_login_required_wrapper
def api_dlp_discovery_add(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    data_type = (data.get("data_type") or "").strip()
    sensitivity = (data.get("sensitivity") or "CONFIDENTIAL").strip().upper()
    location = (data.get("location") or "").strip()
    if not data_type or not location:
        return jsonify({"error": "data_type and location are required"}), 400
    did = _store().add_dlp_data_record(
        engagement_id, data_type, sensitivity, location,
        owner=data.get("owner"),
        access_level=data.get("access_level"),
        estimated_volume=data.get("estimated_volume"),
        format=data.get("format"),
        classification_applied=bool(data.get("classification_applied", False)),
        controls_applied=data.get("controls_applied"),
        notes=data.get("notes"),
        created_by=_actor(),
    )
    _audit("ADD_DLP_DISCOVERY", engagement_id=engagement_id, object_type="DLP_DISCOVERY", object_id=did)
    return jsonify({"record_id": did}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/discovery/<record_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_dlp_discovery_update(engagement_id: str, record_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_dlp_data_record(record_id, data)
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/discovery/<record_id>", methods=["DELETE"])
@_login_required_wrapper
def api_dlp_discovery_delete(engagement_id: str, record_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_dlp_data_record(record_id)
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/flows", methods=["GET"])
@_login_required_wrapper
def api_dlp_flows_list(engagement_id: str):
    return jsonify({"flows": _store().list_data_flows(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/flows", methods=["POST"])
@_login_required_wrapper
def api_dlp_flows_add(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    source = (data.get("source") or "").strip()
    destination = (data.get("destination") or "").strip()
    data_type = (data.get("data_type") or "").strip()
    channel = (data.get("channel") or "").strip()
    if not source or not destination or not data_type or not channel:
        return jsonify({"error": "source, destination, data_type and channel are required"}), 400
    fid = _store().add_data_flow(
        engagement_id, source, destination, data_type, channel,
        sensitivity=data.get("sensitivity", "CONFIDENTIAL"),
        user_role=data.get("user_role"),
        security_control=data.get("security_control"),
        risk_level=data.get("risk_level"),
        observation=data.get("observation"),
        notes=data.get("notes"),
        created_by=_actor(),
    )
    _audit("ADD_DLP_FLOW", engagement_id=engagement_id, object_type="DLP_FLOW", object_id=fid)
    return jsonify({"flow_id": fid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/flows/<flow_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_dlp_flows_update(engagement_id: str, flow_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_data_flow(flow_id, data)
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/flows/<flow_id>", methods=["DELETE"])
@_login_required_wrapper
def api_dlp_flows_delete(engagement_id: str, flow_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    ok = _store().delete_data_flow(flow_id)
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/controls", methods=["GET"])
@_login_required_wrapper
def api_dlp_controls_list(engagement_id: str):
    return jsonify({"controls": _store().list_dlp_controls(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/controls/<control_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_dlp_controls_update(engagement_id: str, control_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_dlp_control(control_id, data, actor=_actor())
    _audit("UPDATE_DLP_CONTROL", engagement_id=engagement_id, object_type="DLP_CONTROL", object_id=control_id,
           details={"status": data.get("status")})
    return jsonify({"ok": ok})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/validations", methods=["GET"])
@_login_required_wrapper
def api_dlp_validations_list(engagement_id: str):
    return jsonify({"validations": _store().list_dlp_validations(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/validations", methods=["POST"])
@_login_required_wrapper
def api_dlp_validations_add(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    channel = (data.get("channel") or "").strip()
    objective = (data.get("test_objective") or data.get("test_description") or "").strip()
    test_data_id = (data.get("test_data_id") or "SYNTHETIC_DATA").strip()
    expected = (data.get("expected_result") or "Enforce control").strip()
    if not channel or not objective:
        return jsonify({"error": "channel and test_objective (or test_description) are required"}), 400
    vid = _store().add_dlp_validation(
        engagement_id, channel, objective, test_data_id, expected,
        date_tested=data.get("date_tested"),
        tested_by=data.get("tested_by") or _actor(),
        actual_result=data.get("actual_result"),
        status=data.get("status", "NOT_TESTED"),
        notes=data.get("notes"),
    )
    _audit("ADD_DLP_VALIDATION", engagement_id=engagement_id, object_type="DLP_VALIDATION", object_id=vid,
           details={"channel": channel, "test_data_id": test_data_id})
    return jsonify({"validation_id": vid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/dlp/validations/<validation_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_dlp_validations_update(engagement_id: str, validation_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_dlp_validation(validation_id, data)
    _audit("UPDATE_DLP_VALIDATION", engagement_id=engagement_id, object_type="DLP_VALIDATION",
           object_id=validation_id, details={"status": data.get("status")})
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Risk Register
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/risk", methods=["GET"])
@_login_required_wrapper
def api_risk_register(engagement_id: str):
    status = request.args.get("status")
    priority = request.args.get("priority")
    entries = _store().list_risk_register(engagement_id, status=status, priority=priority)
    summary = _store().get_risk_summary(engagement_id)
    return jsonify({"risk_register": entries, "summary": summary, "total": len(entries)})


@engagement_bp.route("/api/engagements/<engagement_id>/risk/sync", methods=["POST"])
@_login_required_wrapper
def api_sync_risk_register(engagement_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    count = _get_svc().rebuild_risk_register(engagement_id, actor=_actor())
    return jsonify({"ok": True, "synced": count})


@engagement_bp.route("/api/engagements/<engagement_id>/risk/<entry_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_risk_entry(engagement_id: str, entry_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_risk_register_entry(entry_id, data, actor=_actor())
    _audit("UPDATE_RISK_ENTRY", engagement_id=engagement_id, object_type="RISK_REGISTER",
           object_id=entry_id, details={"changes": list(data.keys())})
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Remediation
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/remediation", methods=["GET"])
@_login_required_wrapper
def api_list_remediation(engagement_id: str):
    actions = _store().list_remediation_actions(engagement_id=engagement_id)
    return jsonify({"actions": actions, "total": len(actions)})


@engagement_bp.route("/api/engagements/<engagement_id>/findings/<finding_id>/remediation", methods=["POST"])
@_login_required_wrapper
def api_add_remediation(engagement_id: str, finding_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    action_taken = (data.get("action_taken") or "").strip()
    if not action_taken:
        return jsonify({"error": "action_taken is required"}), 400
    rid = _store().add_remediation_action(
        finding_id, engagement_id, action_taken,
        assigned_to=data.get("assigned_to"),
        target_date=data.get("target_date"),
        notes=data.get("notes"),
        created_by=_actor(),
    )
    _audit("ADD_REMEDIATION", engagement_id=engagement_id, object_type="REMEDIATION", object_id=rid,
           details={"finding_id": finding_id, "action": action_taken})
    return jsonify({"action_id": rid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/remediation/<action_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_remediation(engagement_id: str, action_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_remediation_action(action_id, data, actor=_actor())
    _audit("UPDATE_REMEDIATION", engagement_id=engagement_id, object_type="REMEDIATION",
           object_id=action_id, details={"status": data.get("status")})
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Retests
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/retests", methods=["GET"])
@_login_required_wrapper
def api_list_retests(engagement_id: str):
    retests = _store().list_retests(engagement_id)
    return jsonify({"retests": retests, "total": len(retests)})


@engagement_bp.route("/api/engagements/<engagement_id>/findings/<finding_id>/retest", methods=["POST"])
@_login_required_wrapper
def api_create_retest(engagement_id: str, finding_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    rid = _store().create_retest(
        finding_id, engagement_id,
        original_finding_summary=data.get("original_finding_summary"),
        remediation_summary=data.get("remediation_summary"),
        retest_by=data.get("retest_by") or _actor(),
        retest_date=data.get("retest_date"),
        notes=data.get("notes"),
    )
    _audit("CREATE_RETEST", engagement_id=engagement_id, object_type="RETEST", object_id=rid,
           details={"finding_id": finding_id})
    return jsonify({"retest_id": rid}), 201


@engagement_bp.route("/api/engagements/<engagement_id>/retests/<retest_id>", methods=["PUT", "PATCH"])
@_login_required_wrapper
def api_update_retest(engagement_id: str, retest_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().update_retest(retest_id, data)
    _audit("UPDATE_RETEST", engagement_id=engagement_id, object_type="RETEST", object_id=retest_id,
           details={"result": data.get("result")})
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Reports
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/reports", methods=["GET"])
@_login_required_wrapper
def api_list_reports(engagement_id: str):
    return jsonify({"reports": _store().list_reports(engagement_id)})


@engagement_bp.route("/api/engagements/<engagement_id>/reports/executive", methods=["GET"])
@_login_required_wrapper
def api_executive_report(engagement_id: str):
    fmt = request.args.get("format", "html").lower()
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return jsonify({"error": "Engagement not found"}), 404
    try:
        from nitesentinels.core.reporter import Reporter
        reporter = Reporter()
        report_data = _store().build_executive_report_data(engagement_id)
        if fmt == "json":
            return jsonify(report_data)
        html = reporter.generate_executive_assessment_html(report_data)
        # Record report generation
        _store().create_report_record(
            engagement_id, "EXECUTIVE",
            title=f"Executive Assessment Report — {eng.get('assessment_name')}",
            generated_by=_actor(),
            format="HTML",
        )
        _audit("GENERATE_REPORT", engagement_id=engagement_id, object_type="REPORT",
               details={"type": "EXECUTIVE", "format": fmt})
        from flask import Response
        return Response(html, mimetype="text/html")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/engagements/<engagement_id>/reports/technical", methods=["GET"])
@_login_required_wrapper
def api_technical_report(engagement_id: str):
    fmt = request.args.get("format", "html").lower()
    eng = _store().get_engagement(engagement_id)
    if not eng:
        return jsonify({"error": "Engagement not found"}), 404
    try:
        from nitesentinels.core.reporter import Reporter
        reporter = Reporter()
        report_data = _store().build_technical_report_data(engagement_id)
        if fmt == "json":
            return jsonify(report_data)
        html = reporter.generate_technical_assessment_html(report_data)
        _store().create_report_record(
            engagement_id, "TECHNICAL",
            title=f"Technical Assessment Report — {eng.get('assessment_name')}",
            generated_by=_actor(),
            format="HTML",
        )
        _audit("GENERATE_REPORT", engagement_id=engagement_id, object_type="REPORT",
               details={"type": "TECHNICAL", "format": fmt})
        from flask import Response
        return Response(html, mimetype="text/html")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@engagement_bp.route("/api/engagements/<engagement_id>/reports/<report_id>/finalize", methods=["POST"])
@_login_required_wrapper
def api_finalize_report(engagement_id: str, report_id: str):
    if not _csrf_ok():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json() or {}
    ok = _store().finalize_report(report_id, reviewed_by=data.get("reviewed_by") or _actor())
    _audit("FINALIZE_REPORT", engagement_id=engagement_id, object_type="REPORT", object_id=report_id)
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# REST API — Audit Log
# ---------------------------------------------------------------------------

@engagement_bp.route("/api/engagements/<engagement_id>/audit", methods=["GET"])
@_login_required_wrapper
def api_engagement_audit_log(engagement_id: str):
    limit = int(request.args.get("limit", 200))
    logs = _store().list_audit_log(engagement_id=engagement_id, limit=limit)
    return jsonify({"logs": logs, "total": len(logs)})
