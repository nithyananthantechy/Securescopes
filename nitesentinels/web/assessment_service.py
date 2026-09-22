"""
NiteSentinel Assessment Service
================================
Business logic layer sitting between Flask routes and the data store.

Responsibilities:
    - Scope enforcement before active scanning
    - Section progress aggregation
    - Risk calculation and formatting
    - Finding import from scanner results
    - Evidence file handling (secure storage, hash verification)
    - Report data preparation

NiteSentinel v2.0 — NITECHSPARK MSME Cybersecurity Assessment Platform
"""

from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime
from typing import Any

from nitesentinels.web.engagement_store import (
    EngagementStore,
    ENGAGEMENT_STATES,
    ASSESSMENT_SECTIONS,
    calculate_risk_priority,
    _now_iso,
    _new_id,
)

# Max evidence file size: 100 MB
MAX_EVIDENCE_FILE_BYTES = 100 * 1024 * 1024

# Allowed evidence file extensions (no executables)
ALLOWED_EVIDENCE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
    ".pdf", ".txt", ".log", ".csv", ".xlsx", ".docx", ".html",
    ".json", ".xml", ".zip", ".7z", ".pcap",
    ".mp4", ".mov",
}

# WARNING: No anti-malware scanning implemented.
# Uploaded evidence files are stored as-is.
# Operators must ensure files come from trusted sources.
EVIDENCE_SECURITY_DISCLAIMER = (
    "WARNING: Uploaded files are not scanned for malware. "
    "Only upload evidence files from trusted, controlled sources."
)


class AssessmentService:
    """
    Service layer for NITECHSPARK assessment lifecycle management.
    All route handlers should call service methods, not store methods directly.
    """

    def __init__(self, store: EngagementStore, evidence_base_dir: str = "data/evidence"):
        self.store = store
        self.evidence_base_dir = evidence_base_dir

    # ------------------------------------------------------------------ #
    # Scope & Authorization Enforcement
    # ------------------------------------------------------------------ #

    def authorize_scan(
        self,
        engagement_id: str | None,
        target: str,
        actor: str = "system",
    ) -> tuple[bool, str]:
        """
        Server-side authorization check before any active scan.

        Returns (is_authorized: bool, reason: str).

        Rules:
          1. If no engagement_id: scan is legacy/direct — allowed (backward compat).
          2. Engagement must exist and not be DRAFT.
          3. Engagement authorization_status must be AUTHORIZED.
          4. Target must be within engagement scope.
        """
        if not engagement_id:
            # Legacy mode — no engagement context, allow existing scanner flows
            return True, "Legacy scan (no engagement context)"

        ok, reason = self.store.validate_scope(engagement_id)
        if not ok:
            self.store.audit(
                actor, "SCAN_BLOCKED",
                engagement_id=engagement_id,
                object_type="SCAN",
                object_id=target,
                result="BLOCKED",
                details={"reason": reason, "target": target},
            )
            return False, reason

        if not self.store.is_target_in_scope(engagement_id, target):
            msg = f"Target '{target}' is outside the authorized scope. Scanning blocked."
            self.store.audit(
                actor, "SCAN_OUT_OF_SCOPE",
                engagement_id=engagement_id,
                object_type="SCAN",
                object_id=target,
                result="BLOCKED",
                details={"reason": msg, "target": target},
            )
            return False, msg

        self.store.audit(
            actor, "SCAN_AUTHORIZED",
            engagement_id=engagement_id,
            object_type="SCAN",
            object_id=target,
            result="SUCCESS",
            details={"target": target},
        )
        return True, "Authorized"

    # ------------------------------------------------------------------ #
    # Client Operations
    # ------------------------------------------------------------------ #

    def create_client(self, data: dict, actor: str = "system") -> tuple[str, dict]:
        """Create a client record. Returns (client_id, client_dict)."""
        company_name = (data.get("company_name") or data.get("name") or "").strip()
        if not company_name:
            raise ValueError("company_name is required")
        cid = self.store.create_client(
            company_name,
            industry=data.get("industry"),
            location=data.get("location"),
            contact_person=data.get("contact_person") or data.get("contact_name"),
            email=data.get("email") or data.get("contact_email"),
            phone=data.get("phone"),
            website=data.get("website"),
            notes=data.get("notes"),
            created_by=actor,
        )
        self.store.audit(
            actor, "CREATE_CLIENT",
            object_type="CLIENT", object_id=cid,
            details={"company_name": company_name},
        )
        return cid, self.store.get_client(cid)

    # ------------------------------------------------------------------ #
    # Engagement Operations
    # ------------------------------------------------------------------ #

    def create_engagement(self, client_id: str, data: dict, actor: str = "system") -> tuple[str, dict]:
        """Create an engagement and initialize all section responses."""
        assessment_name = (data.get("assessment_name") or data.get("title") or "").strip()
        if not assessment_name:
            raise ValueError("assessment_name is required")
        if not self.store.get_client(client_id):
            raise ValueError("Client not found")

        eid = self.store.create_engagement(
            client_id, assessment_name,
            assessment_type=data.get("assessment_type", "IT_SECURITY_ASSESSMENT"),
            start_date=data.get("start_date"),
            end_date=data.get("end_date"),
            assessor=data.get("assessor") or data.get("lead_assessor") or actor,
            reviewer=data.get("reviewer"),
            scope_summary=data.get("scope_summary"),
            methodology=data.get("methodology"),
            notes=data.get("notes"),
            org_id=data.get("org_id"),
            created_by=actor,
        )
        # Initialize all section question responses in background
        self.store.initialize_all_sections(eid)
        # Initialize DLP controls
        self.store.initialize_dlp_controls(eid)
        self.store.audit(
            actor, "CREATE_ENGAGEMENT",
            engagement_id=eid, object_type="ENGAGEMENT", object_id=eid,
            details={"assessment_name": assessment_name, "client_id": client_id},
        )
        return eid, self.store.get_engagement(eid)

    def authorize_engagement(
        self,
        engagement_id: str,
        authorization_document: str,
        authorized_by: str,
        actor: str = "system",
    ) -> tuple[bool, str]:
        """Transition engagement to AUTHORIZED state."""
        eng = self.store.get_engagement(engagement_id)
        if not eng:
            return False, "Engagement not found"
        ok = self.store.update_engagement(engagement_id, {
            "authorization_status": "AUTHORIZED",
            "authorization_document": authorization_document,
            "authorized_by": authorized_by,
            "authorization_date": _now_iso(),
            "status": "AUTHORIZED",
        })
        if ok:
            self.store.audit(
                actor, "AUTHORIZE_ENGAGEMENT",
                engagement_id=engagement_id, object_type="ENGAGEMENT", object_id=engagement_id,
                details={"authorized_by": authorized_by, "document": authorization_document},
            )
        return ok, "Authorized" if ok else "Update failed"

    def get_engagement_dashboard(self, engagement_id: str) -> dict:
        """Full engagement overview for the central workspace page."""
        eng = self.store.get_engagement(engagement_id)
        if not eng:
            return {"error": "Engagement not found"}
        overview = self.store.get_assessment_overview(engagement_id)
        scope = self.store.list_scope(engagement_id)
        assets = self.store.list_assets(engagement_id)
        reports = self.store.list_reports(engagement_id)
        remediation = self.store.list_remediation_actions(engagement_id=engagement_id)
        pending_remediation = [r for r in remediation if r.get("status") not in ("COMPLETED", "RISK_ACCEPTED")]
        retests = self.store.list_retests(engagement_id)
        return {
            "engagement": eng,
            "scope": scope,
            "assets": assets,
            "overview": overview,
            "reports": reports,
            "pending_remediation_count": len(pending_remediation),
            "total_retest_count": len(retests),
            "completed_retest_count": len([r for r in retests if r.get("result") not in ("NOT_RETESTED", None)]),
        }

    # ------------------------------------------------------------------ #
    # Assessment Responses
    # ------------------------------------------------------------------ #

    def update_response_and_create_finding(
        self,
        engagement_id: str,
        question_id: str,
        response_data: dict,
        actor: str = "system",
    ) -> dict:
        """
        Update a response and optionally auto-create a finding if status is FAIL.
        Returns {"response": ..., "finding_id": ... or None}.
        """
        resp = self.store.get_or_create_response(engagement_id, question_id)
        resp_id = resp["id"]
        status = response_data.get("status", "NOT_ASSESSED")
        updates = {
            "status": status,
            "response_text": response_data.get("response_text"),
            "observation": response_data.get("observation"),
            "recommendation": response_data.get("recommendation"),
            "risk_note": response_data.get("risk_note"),
            "assessed_by": actor,
            "assessed_at": _now_iso(),
            "is_not_applicable": 1 if status == "NOT_APPLICABLE" else 0,
            "na_reason": response_data.get("na_reason"),
        }
        self.store.update_response(resp_id, updates, actor=actor)
        self.store.audit(
            actor, "UPDATE_RESPONSE",
            engagement_id=engagement_id, object_type="RESPONSE", object_id=resp_id,
            details={"question_id": question_id, "status": status},
        )
        finding_id = None
        # Auto-create a finding for FAIL or PARTIAL responses when auto_finding is requested
        if status in ("FAIL", "PARTIAL") and response_data.get("auto_create_finding"):
            q = self.store.get_question(question_id)
            if q:
                finding_id = self.store.create_finding(
                    engagement_id,
                    section=q.get("section", "GENERAL"),
                    title=q.get("question_text", "Finding from Assessment"),
                    description=response_data.get("observation") or "No observation provided.",
                    severity=q.get("severity_hint") or ("HIGH" if status == "FAIL" else "MEDIUM"),
                    question_id=question_id,
                    category=q.get("section"),
                    recommendation=response_data.get("recommendation"),
                    framework_refs=self.store._parse_json_field(q.get("framework_refs"), {}),
                    created_by=actor,
                )
                if finding_id:
                    # Link finding back to response
                    existing_fids = self.store._parse_json_field(resp.get("finding_ids"), [])
                    existing_fids.append(finding_id)
                    self.store.update_response(resp_id, {"finding_ids": existing_fids})
                    self.store.audit(
                        actor, "AUTO_CREATE_FINDING",
                        engagement_id=engagement_id, object_type="FINDING", object_id=finding_id,
                        details={"from_response": resp_id, "question_id": question_id},
                    )
        return {"response": self.store.get_or_create_response(engagement_id, question_id), "finding_id": finding_id}

    # ------------------------------------------------------------------ #
    # Evidence File Handling
    # ------------------------------------------------------------------ #

    def _evidence_dir(self, engagement_id: str) -> str:
        path = os.path.join(self.evidence_base_dir, engagement_id)
        os.makedirs(path, exist_ok=True)
        return path

    def store_evidence_file(
        self,
        engagement_id: str,
        file_stream,
        original_filename: str,
        uploaded_by: str,
        *,
        finding_id: str | None = None,
        question_id: str | None = None,
        description: str = "",
        sensitivity: str = "CONFIDENTIAL",
        evidence_type: str = "SCREENSHOT",
        notes: str | None = None,
    ) -> tuple[str, str]:
        """
        Securely store an uploaded evidence file.

        Security:
        - Extension whitelisted
        - Filename sanitized
        - Stored in data/evidence/<engagement_id>/
        - SHA-256 computed after write
        - No execution permitted

        WARNING: Files are NOT scanned for malware.

        Returns (evidence_id, safe_filename).
        """
        # Extension check
        _, ext = os.path.splitext(original_filename)
        ext = ext.lower()
        if ext not in ALLOWED_EVIDENCE_EXTENSIONS:
            raise ValueError(
                f"File type '{ext}' is not allowed. "
                f"Permitted: {', '.join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))}"
            )

        # Sanitize filename
        safe_name = _new_id() + ext
        dest_dir = self._evidence_dir(engagement_id)
        dest_path = os.path.join(dest_dir, safe_name)

        # Write file
        file_stream.seek(0)
        data = file_stream.read(MAX_EVIDENCE_FILE_BYTES + 1)
        if len(data) > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError(f"File too large. Maximum size is {MAX_EVIDENCE_FILE_BYTES // (1024*1024)} MB.")

        with open(dest_path, "wb") as f:
            f.write(data)

        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()

        evidence_id = self.store.add_evidence(
            engagement_id,
            description=description or original_filename,
            collected_by=uploaded_by,
            evidence_type=evidence_type,
            finding_id=finding_id,
            question_id=question_id,
            source=f"Upload: {original_filename}",
            file_path=dest_path,
            file_name=safe_name,
            file_size=file_size,
            sensitivity=sensitivity,
            notes=notes,
        )
        self.store.audit(
            uploaded_by, "UPLOAD_EVIDENCE",
            engagement_id=engagement_id, object_type="EVIDENCE", object_id=evidence_id,
            details={
                "original_filename": original_filename,
                "safe_filename": safe_name,
                "sha256": sha256,
                "size": file_size,
                "finding_id": finding_id,
                "sensitivity": sensitivity,
                "disclaimer": EVIDENCE_SECURITY_DISCLAIMER,
            },
        )
        return evidence_id, safe_name

    def get_evidence_file_path(
        self,
        evidence_id: str,
        requesting_user: str,
        engagement_id: str,
    ) -> tuple[str | None, str]:
        """
        Return safe file path for a given evidence record.
        Enforces that evidence belongs to the requested engagement.
        Returns (path, error_message).
        """
        ev = self.store.get_evidence(evidence_id)
        if not ev:
            return None, "Evidence not found"
        if ev.get("engagement_id") != engagement_id:
            self.store.audit(
                requesting_user, "EVIDENCE_ACCESS_DENIED",
                engagement_id=engagement_id, object_type="EVIDENCE", object_id=evidence_id,
                result="BLOCKED",
                details={"reason": "Evidence belongs to different engagement"},
            )
            return None, "Access denied"
        path = ev.get("file_path")
        if not path or not os.path.exists(path):
            return None, "File not found on disk"
        self.store.audit(
            requesting_user, "DOWNLOAD_EVIDENCE",
            engagement_id=engagement_id, object_type="EVIDENCE", object_id=evidence_id,
            details={"file_path": path, "sensitivity": ev.get("sensitivity")},
        )
        return path, "OK"

    # ------------------------------------------------------------------ #
    # Finding Import from Scanner Results
    # ------------------------------------------------------------------ #

    def import_scan_results(
        self,
        engagement_id: str,
        scan_result: dict,
        section: str = "VULNERABILITY_ASSESSMENT",
        actor: str = "system",
    ) -> list[str]:
        """
        Import scanner check results into engagement findings.
        Only imports FAIL / WARNING checks.
        Returns list of created finding_ids.
        """
        created_ids = []
        checks = scan_result.get("checks") or []
        target = scan_result.get("hostname") or scan_result.get("target") or "Unknown"
        for check in checks:
            if check.get("status") not in ("FAIL", "WARNING"):
                continue
            fid = self.store.import_scan_finding(
                engagement_id, check, section=section,
                affected_asset=target, created_by=actor,
            )
            if fid:
                created_ids.append(fid)
        # Sync to risk register
        if created_ids:
            self.store.sync_findings_to_risk_register(engagement_id)
        self.store.audit(
            actor, "IMPORT_SCAN_FINDINGS",
            engagement_id=engagement_id, object_type="SCAN", object_id=target,
            details={"section": section, "imported": len(created_ids), "total_checks": len(checks)},
        )
        return created_ids

    # ------------------------------------------------------------------ #
    # Risk Register
    # ------------------------------------------------------------------ #

    def rebuild_risk_register(self, engagement_id: str, actor: str = "system") -> int:
        """Sync all findings to risk register and return count of new entries."""
        count = self.store.sync_findings_to_risk_register(engagement_id)
        self.store.audit(
            actor, "SYNC_RISK_REGISTER",
            engagement_id=engagement_id, object_type="RISK_REGISTER",
            details={"new_entries": count},
        )
        return count

    # ------------------------------------------------------------------ #
    # Progress / Summary Helpers
    # ------------------------------------------------------------------ #

    def get_full_progress(self, engagement_id: str) -> dict:
        """Return a JSON-serializable progress object for the overview page."""
        overview = self.store.get_assessment_overview(engagement_id)
        total_sections = len(ASSESSMENT_SECTIONS)
        completed = sum(
            1 for s in overview["sections"].values()
            if s["status"] in ("COMPLETED", "NOT_APPLICABLE")
        )
        in_progress = sum(
            1 for s in overview["sections"].values()
            if s["status"] == "IN_PROGRESS"
        )
        not_started = total_sections - completed - in_progress
        overall_pct = int((completed / total_sections) * 100) if total_sections else 0
        return {
            **overview,
            "progress_pct": overall_pct,
            "sections_completed": completed,
            "sections_in_progress": in_progress,
            "sections_not_started": not_started,
            "total_sections": total_sections,
        }
