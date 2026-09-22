"""
NiteSentinel Engagement Store
=============================
SQLite Data Access Layer for the professional client-facing assessment lifecycle:

    CLIENT → ENGAGEMENT → SCOPE → ASSESSMENT → QUESTIONNAIRE/CONTROLS
    → EVIDENCE → FINDINGS → RISK REGISTER → REMEDIATION → RETEST → REPORTS

Tables created (all CREATE TABLE IF NOT EXISTS — safe to add alongside existing DB):
    clients, engagements, engagement_scope, eng_assets,
    assessment_templates, assessment_questions, assessment_responses,
    findings, evidence, dlp_data_discovery, dlp_data_flows, dlp_controls, dlp_validations,
    risk_register, remediation_actions, retests, assessment_reports, engagement_audit_log

Design principles:
    - All IDs are UUID hex strings
    - Soft-delete where noted (is_deleted / is_active columns)
    - Timestamps in ISO 8601 UTC
    - Assessment lifecycle uses explicit state machine
    - Finding lifecycle: OPEN → IN_PROGRESS → READY_FOR_RETEST → RETESTED → RESOLVED
                         OPEN → RISK_ACCEPTED
    - Response status: PASS | PARTIAL | FAIL | NOT_APPLICABLE | NOT_ASSESSED
    - Evidence sensitivity: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
    - Risk = f(severity, likelihood, impact, asset_criticality, data_sensitivity, existing_controls)
    - Assessor override supported with mandatory justification

NiteSentinel v2.0 — NITECHSPARK MSME Cybersecurity Assessment Platform
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Constants / Enumerations
# ---------------------------------------------------------------------------

ENGAGEMENT_STATES = [
    "DRAFT",
    "AUTHORIZED",
    "DISCOVERY",
    "ASSESSING",
    "ASSESSMENT",
    "VALIDATION",
    "REPORTING",
    "REMEDIATION",
    "RETEST",
    "COMPLETED",
    "CLOSED",
    "ARCHIVED",
]

FINDING_STATUSES = [
    "OPEN",
    "IN_PROGRESS",
    "READY_FOR_RETEST",
    "RETESTED",
    "RESOLVED",
    "RISK_ACCEPTED",
]

RESPONSE_STATUSES = ["PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "NOT_ASSESSED"]

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

LIKELIHOOD_LEVELS = ["VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW"]

IMPACT_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]

EVIDENCE_TYPES = [
    "SCREENSHOT",
    "LOG_EXPORT",
    "SCAN_RESULT",
    "DOCUMENT",
    "INTERVIEW_NOTE",
    "POLICY_REVIEW",
    "CONFIGURATION",
    "VALIDATION_RESULT",
    "OTHER",
]

EVIDENCE_SENSITIVITY = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]

SECTION_STATUSES = ["NOT_STARTED", "IN_PROGRESS", "COMPLETED", "NOT_APPLICABLE"]

ASSESSMENT_SECTIONS = [
    "ASSET_DISCOVERY",
    "NETWORK",
    "SERVERS",
    "ENDPOINTS",
    "IAM",
    "BACKUP",
    "WEB_DOMAIN_EMAIL",
    "DLP",
    "VULNERABILITY_ASSESSMENT",
    "COMPLIANCE",
]

COMPLIANCE_FRAMEWORKS = [
    "NIST_CSF_2",
    "CIS_CONTROLS",
    "ISO_27001",
    "PCI_DSS",
    "DPDP_2023",
]

# Risk priority calculation weights
SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
LIKELIHOOD_WEIGHT = {"VERY_HIGH": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "VERY_LOW": 1}
IMPACT_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NEGLIGIBLE": 1}
CRITICALITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
SENSITIVITY_WEIGHT = {"RESTRICTED": 5, "CONFIDENTIAL": 4, "INTERNAL": 3, "PUBLIC": 1}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file for chain-of-custody."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def calculate_risk_priority(
    severity: str,
    likelihood: str,
    impact: str,
    asset_criticality: str | None = None,
    data_sensitivity: str | None = None,
    existing_controls_mitigate: bool = False,
) -> tuple[int, str]:
    """
    Calculate a composite risk priority score.

    Returns (score: int, label: str) where label is one of:
        CRITICAL (20+), HIGH (14-19), MEDIUM (8-13), LOW (1-7)

    Model:
        base = severity_weight * likelihood_weight * impact_weight
        adjustments for asset criticality, data sensitivity, existing controls

    Score range: 1 – 375 raw, normalized to 1-25 range.
    """
    sev = SEVERITY_WEIGHT.get((severity or "").upper(), 3)
    lik = LIKELIHOOD_WEIGHT.get((likelihood or "").upper(), 3)
    imp = IMPACT_WEIGHT.get((impact or "").upper(), 3)
    crit = CRITICALITY_WEIGHT.get((asset_criticality or "").upper(), 3)
    sens = SENSITIVITY_WEIGHT.get((data_sensitivity or "").upper(), 3)

    raw = sev * lik * imp * crit * sens  # max = 5^5 = 3125
    # Normalize to 1–25 using cube-root scale
    normalized = max(1, min(25, round((raw / 3125) ** (1 / 3) * 25)))

    if existing_controls_mitigate:
        normalized = max(1, normalized - 3)

    if normalized >= 20:
        label = "CRITICAL"
    elif normalized >= 14:
        label = "HIGH"
    elif normalized >= 8:
        label = "MEDIUM"
    else:
        label = "LOW"

    return (normalized, label)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
-- ====================================================================
-- CLIENTS
-- ====================================================================
CREATE TABLE IF NOT EXISTS clients (
    id              TEXT PRIMARY KEY,
    company_name    TEXT NOT NULL,
    industry        TEXT,
    location        TEXT,
    contact_person  TEXT,
    email           TEXT,
    phone           TEXT,
    website         TEXT,
    notes           TEXT,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    is_deleted      INTEGER NOT NULL DEFAULT 0
);

-- ====================================================================
-- ENGAGEMENTS
-- ====================================================================
CREATE TABLE IF NOT EXISTS engagements (
    id                      TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL REFERENCES clients(id),
    assessment_name         TEXT NOT NULL,
    assessment_type         TEXT NOT NULL DEFAULT 'IT_SECURITY_ASSESSMENT',
    status                  TEXT NOT NULL DEFAULT 'DRAFT',
    start_date              TEXT,
    end_date                TEXT,
    assessor                TEXT,
    reviewer                TEXT,
    scope_summary           TEXT,
    authorization_status    TEXT NOT NULL DEFAULT 'PENDING',
    authorization_document  TEXT,
    authorization_date      TEXT,
    authorized_by           TEXT,
    methodology             TEXT,
    notes                   TEXT,
    org_id                  TEXT,
    created_by              TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    is_deleted              INTEGER NOT NULL DEFAULT 0
);

-- ====================================================================
-- ENGAGEMENT SCOPE
-- ====================================================================
CREATE TABLE IF NOT EXISTS engagement_scope (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    scope_type      TEXT NOT NULL,  -- DOMAIN, IP_RANGE, SUBNET, ASSET_ID, URL, EXCLUSION
    value           TEXT NOT NULL,
    description     TEXT,
    excluded        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

-- ====================================================================
-- ENGAGEMENT ASSETS
-- ====================================================================
CREATE TABLE IF NOT EXISTS eng_assets (
    id                      TEXT PRIMARY KEY,
    engagement_id           TEXT NOT NULL REFERENCES engagements(id),
    asset_id                TEXT,  -- references ham_assets.id if applicable
    asset_type              TEXT,  -- SERVER, WORKSTATION, FIREWALL, SWITCH, IOT, WEB_APP
    hostname                TEXT,
    ip_address              TEXT,
    os                      TEXT,
    criticality             TEXT NOT NULL DEFAULT 'MEDIUM',
    data_sensitivity        TEXT NOT NULL DEFAULT 'INTERNAL',
    include_in_assessment   INTEGER NOT NULL DEFAULT 1,
    assessment_notes        TEXT,
    created_at              TEXT NOT NULL
);

-- ====================================================================
-- ASSESSMENT TEMPLATES
-- ====================================================================
CREATE TABLE IF NOT EXISTS assessment_templates (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    section         TEXT NOT NULL,
    description     TEXT,
    version         TEXT NOT NULL DEFAULT '1.0',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ====================================================================
-- ASSESSMENT QUESTIONS / CONTROLS
-- ====================================================================
CREATE TABLE IF NOT EXISTS assessment_questions (
    id              TEXT PRIMARY KEY,
    template_id     TEXT REFERENCES assessment_templates(id),
    section         TEXT NOT NULL,
    question_ref    TEXT,  -- e.g. IAM-01
    question_text   TEXT NOT NULL,
    guidance        TEXT,
    evidence_hint   TEXT,
    severity_hint   TEXT,
    framework_refs  TEXT,  -- JSON: {"NIST_CSF_2": "GV.SC-07", "ISO_27001": "A.9.2"}
    order_index     INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

-- ====================================================================
-- ASSESSMENT RESPONSES
-- ====================================================================
CREATE TABLE IF NOT EXISTS assessment_responses (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    question_id         TEXT NOT NULL REFERENCES assessment_questions(id),
    section             TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'NOT_ASSESSED',  -- PASS|PARTIAL|FAIL|NOT_APPLICABLE|NOT_ASSESSED
    response_text       TEXT,
    observation         TEXT,
    recommendation      TEXT,
    risk_note           TEXT,
    evidence_ids        TEXT,  -- JSON array of evidence IDs
    finding_ids         TEXT,  -- JSON array of finding IDs created from this response
    reviewed_by         TEXT,
    assessed_by         TEXT,
    assessed_at         TEXT,
    updated_at          TEXT NOT NULL,
    is_not_applicable   INTEGER NOT NULL DEFAULT 0,
    na_reason           TEXT
);

-- ====================================================================
-- FINDINGS
-- ====================================================================
CREATE TABLE IF NOT EXISTS findings (
    id                          TEXT PRIMARY KEY,
    engagement_id               TEXT NOT NULL REFERENCES engagements(id),
    section                     TEXT NOT NULL,
    question_id                 TEXT REFERENCES assessment_questions(id),
    finding_ref                 TEXT,  -- e.g. F-001
    title                       TEXT NOT NULL,
    category                    TEXT,
    description                 TEXT NOT NULL,
    affected_asset              TEXT,
    asset_id                    TEXT REFERENCES eng_assets(id),
    severity                    TEXT NOT NULL DEFAULT 'MEDIUM',
    likelihood                  TEXT NOT NULL DEFAULT 'MEDIUM',
    impact                      TEXT NOT NULL DEFAULT 'MEDIUM',
    asset_criticality           TEXT DEFAULT 'MEDIUM',
    data_sensitivity            TEXT DEFAULT 'INTERNAL',
    existing_controls           TEXT,
    controls_mitigate           INTEGER NOT NULL DEFAULT 0,
    risk_score                  INTEGER,
    risk_priority               TEXT,  -- CRITICAL|HIGH|MEDIUM|LOW (calculated)
    risk_priority_override      TEXT,  -- assessor override
    risk_override_justification TEXT,
    business_impact             TEXT,
    technical_impact            TEXT,
    recommendation              TEXT,
    remediation_guidance        TEXT,
    retest_requirement          TEXT,
    reference                   TEXT,
    framework_refs              TEXT,  -- JSON
    evidence_ids                TEXT,  -- JSON array
    owner                       TEXT,
    status                      TEXT NOT NULL DEFAULT 'OPEN',
    remediation_status          TEXT DEFAULT 'NOT_STARTED',
    retest_status               TEXT DEFAULT 'PENDING',
    due_date                    TEXT,
    closed_at                   TEXT,
    closed_by                   TEXT,
    is_demo                     INTEGER NOT NULL DEFAULT 0,
    created_by                  TEXT,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL
);

-- ====================================================================
-- EVIDENCE
-- ====================================================================
CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    finding_id      TEXT REFERENCES findings(id),
    question_id     TEXT REFERENCES assessment_questions(id),
    evidence_type   TEXT NOT NULL DEFAULT 'OTHER',
    description     TEXT NOT NULL,
    source          TEXT,
    collected_by    TEXT,
    collected_at    TEXT NOT NULL,
    sha256          TEXT,
    file_path       TEXT,
    file_name       TEXT,
    file_size       INTEGER,
    sensitivity     TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    retention_days  INTEGER DEFAULT 2555,  -- ~7 years
    notes           TEXT,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

-- ====================================================================
-- DLP — DATA DISCOVERY
-- ====================================================================
CREATE TABLE IF NOT EXISTS dlp_data_discovery (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    data_type       TEXT NOT NULL,  -- Customer PII, Financial, IP, HR, Health, Source Code
    sensitivity     TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    location        TEXT NOT NULL,  -- Where stored
    owner           TEXT,
    access_level    TEXT,           -- Who can access it
    estimated_volume TEXT,
    format          TEXT,           -- Structured/Unstructured, DB/Files/Email
    classification_applied INTEGER NOT NULL DEFAULT 0,
    controls_applied TEXT,          -- What controls exist
    notes           TEXT,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ====================================================================
-- DLP — DATA FLOWS
-- ====================================================================
CREATE TABLE IF NOT EXISTS dlp_data_flows (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    source          TEXT NOT NULL,
    destination     TEXT NOT NULL,
    data_type       TEXT NOT NULL,
    sensitivity     TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    user_role       TEXT,
    channel         TEXT NOT NULL,  -- Email, USB, Cloud, Browser, Git, FileShare, VPN
    security_control TEXT,
    risk_level      TEXT,
    observation     TEXT,
    notes           TEXT,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ====================================================================
-- DLP — SECURITY CONTROLS ASSESSMENT
-- ====================================================================
CREATE TABLE IF NOT EXISTS dlp_controls (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    control_area    TEXT NOT NULL,  -- EMAIL|USB|CLOUD|BROWSER|GIT|FILE_SHARE|ENDPOINT|VPN|ACCESS_CONTROL|LOGGING|DLP_POLICY
    status          TEXT NOT NULL DEFAULT 'NOT_ASSESSED',
    observation     TEXT,
    recommendation  TEXT,
    evidence_ids    TEXT,   -- JSON array
    risk_level      TEXT,
    assessed_by     TEXT,
    assessed_at     TEXT,
    updated_at      TEXT NOT NULL
);

-- ====================================================================
-- DLP — CONTROLLED VALIDATION
-- ====================================================================
CREATE TABLE IF NOT EXISTS dlp_validations (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    validation_ref      TEXT,       -- e.g. DLP-VAL-001
    channel             TEXT NOT NULL,
    test_objective      TEXT NOT NULL,
    test_data_id        TEXT NOT NULL,  -- Synthetic data identifier ONLY
    date_tested         TEXT,
    tested_by           TEXT,
    expected_result     TEXT NOT NULL,
    actual_result       TEXT,
    status              TEXT NOT NULL DEFAULT 'NOT_TESTED',  -- PASS|PARTIAL|FAIL|NOT_TESTED
    evidence_ids        TEXT,   -- JSON array
    notes               TEXT,
    WARNING             TEXT DEFAULT 'SYNTHETIC TEST DATA ONLY - NO REAL CONFIDENTIAL DATA',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- ====================================================================
-- RISK REGISTER
-- ====================================================================
CREATE TABLE IF NOT EXISTS risk_register (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT NOT NULL REFERENCES engagements(id),
    finding_id          TEXT REFERENCES findings(id),
    risk_ref            TEXT,  -- e.g. RR-001
    category            TEXT,
    asset               TEXT,
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL DEFAULT 'MEDIUM',
    likelihood          TEXT NOT NULL DEFAULT 'MEDIUM',
    impact              TEXT NOT NULL DEFAULT 'MEDIUM',
    risk_score          INTEGER,
    risk_priority       TEXT,
    risk_priority_override TEXT,
    risk_override_justification TEXT,
    evidence_ids        TEXT,  -- JSON array
    recommendation      TEXT,
    owner               TEXT,
    due_date            TEXT,
    status              TEXT NOT NULL DEFAULT 'OPEN',
    retest_status       TEXT DEFAULT 'PENDING',
    treatment           TEXT,  -- MITIGATE|ACCEPT|TRANSFER|AVOID
    framework_refs      TEXT,  -- JSON
    notes               TEXT,
    created_by          TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- ====================================================================
-- REMEDIATION ACTIONS
-- ====================================================================
CREATE TABLE IF NOT EXISTS remediation_actions (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL REFERENCES findings(id),
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    action_taken    TEXT NOT NULL,
    assigned_to     TEXT,
    target_date     TEXT,
    completed_date  TEXT,
    status          TEXT NOT NULL DEFAULT 'NOT_STARTED',  -- NOT_STARTED|IN_PROGRESS|COMPLETED|RISK_ACCEPTED
    evidence_path   TEXT,
    evidence_ids    TEXT,  -- JSON array
    verified_by     TEXT,
    verified_at     TEXT,
    notes           TEXT,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ====================================================================
-- RETESTS
-- ====================================================================
CREATE TABLE IF NOT EXISTS retests (
    id                      TEXT PRIMARY KEY,
    finding_id              TEXT NOT NULL REFERENCES findings(id),
    engagement_id           TEXT NOT NULL REFERENCES engagements(id),
    retest_ref              TEXT,   -- e.g. RT-001
    original_finding_summary TEXT,
    remediation_summary     TEXT,
    retest_by               TEXT,
    retest_date             TEXT,
    result                  TEXT,   -- REMEDIATED|PARTIAL|NOT_REMEDIATED|NOT_RETESTED
    original_evidence_ids   TEXT,   -- JSON
    remediation_evidence_ids TEXT,  -- JSON
    retest_evidence_ids     TEXT,   -- JSON
    notes                   TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

-- ====================================================================
-- ASSESSMENT REPORTS
-- ====================================================================
CREATE TABLE IF NOT EXISTS assessment_reports (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    document_id     TEXT NOT NULL,  -- e.g. RPT-2026-0001
    report_type     TEXT NOT NULL,  -- EXECUTIVE|TECHNICAL|DLP|IAM|COMPLIANCE
    version         TEXT NOT NULL DEFAULT '1.0',
    title           TEXT NOT NULL,
    generated_by    TEXT,
    reviewed_by     TEXT,
    generated_at    TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    format          TEXT NOT NULL DEFAULT 'HTML',  -- HTML|PDF|XLSX
    file_path       TEXT,
    sha256          TEXT,
    status          TEXT NOT NULL DEFAULT 'DRAFT',  -- DRAFT|FINAL|SUPERSEDED
    classification  TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    notes           TEXT
);

-- ====================================================================
-- ENGAGEMENT AUDIT LOG
-- ====================================================================
CREATE TABLE IF NOT EXISTS engagement_audit_log (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    object_type     TEXT,
    object_id       TEXT,
    result          TEXT NOT NULL DEFAULT 'SUCCESS',
    details         TEXT,   -- JSON
    ip_address      TEXT,
    timestamp       TEXT NOT NULL
);

-- ====================================================================
-- INDEXES
-- ====================================================================
CREATE INDEX IF NOT EXISTS idx_engagements_client ON engagements(client_id);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_eng_assets_engagement ON eng_assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scope_engagement ON engagement_scope(engagement_id);
CREATE INDEX IF NOT EXISTS idx_responses_engagement ON assessment_responses(engagement_id);
CREATE INDEX IF NOT EXISTS idx_responses_question ON assessment_responses(question_id);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_evidence_engagement ON evidence(engagement_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_dlp_flows_engagement ON dlp_data_flows(engagement_id);
CREATE INDEX IF NOT EXISTS idx_dlp_controls_engagement ON dlp_controls(engagement_id);
CREATE INDEX IF NOT EXISTS idx_risk_register_engagement ON risk_register(engagement_id);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_actions(finding_id);
CREATE INDEX IF NOT EXISTS idx_retests_finding ON retests(finding_id);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON engagement_audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON engagement_audit_log(timestamp);
"""

# ---------------------------------------------------------------------------
# Default assessment question bank
# ---------------------------------------------------------------------------

_DEFAULT_QUESTIONS: list[dict] = [
    # --- IAM ---
    {"section": "IAM", "ref": "IAM-01", "text": "Are user accounts reviewed periodically (e.g., quarterly)?",
     "guidance": "Verify evidence of periodic user access reviews. Check if stale accounts exist.",
     "evidence_hint": "User access review policy, last review report, AD/LDAP export.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-01", "ISO_27001": "A.9.2.5", "CIS_CONTROLS": "5.3"}},

    {"section": "IAM", "ref": "IAM-02", "text": "Is Multi-Factor Authentication (MFA) enforced for privileged accounts?",
     "guidance": "Verify MFA is mandatory for admin, IT staff, and remote access accounts.",
     "evidence_hint": "MFA policy, Conditional Access rules, admin account list.",
     "severity_hint": "CRITICAL",
     "frameworks": {"NIST_CSF_2": "PR.AA-03", "ISO_27001": "A.9.4.2", "CIS_CONTROLS": "6.5"}},

    {"section": "IAM", "ref": "IAM-03", "text": "Are former employee accounts disabled immediately upon offboarding?",
     "guidance": "Verify offboarding SLA and evidence that accounts are deactivated on or before last working day.",
     "evidence_hint": "HR offboarding process, IAM provisioning/deprovisioning records.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-02", "ISO_27001": "A.9.2.6", "CIS_CONTROLS": "5.2"}},

    {"section": "IAM", "ref": "IAM-04", "text": "Are privileged accounts separated from standard user accounts?",
     "guidance": "Admin accounts should not be used for daily browsing/email. Separate admin IDs required.",
     "evidence_hint": "Account naming policy, sample privileged account list.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-05", "ISO_27001": "A.9.2.3", "CIS_CONTROLS": "5.4"}},

    {"section": "IAM", "ref": "IAM-05", "text": "Is a least-privilege access model enforced?",
     "guidance": "Users should have only the access required for their role. Verify RBAC controls.",
     "evidence_hint": "Role definitions, access matrix, sample permission reviews.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-05", "ISO_27001": "A.9.1.2", "CIS_CONTROLS": "6.1"}},

    {"section": "IAM", "ref": "IAM-06", "text": "Is a password policy enforced (length, complexity, expiry)?",
     "guidance": "Verify password policy requirements: min length ≥12, complexity, expiry interval.",
     "evidence_hint": "Group Policy / Password Policy settings, Active Directory extract.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-01", "ISO_27001": "A.9.4.3", "CIS_CONTROLS": "5.2"}},

    {"section": "IAM", "ref": "IAM-07", "text": "Is MFA enforced for remote access (VPN/RDP)?",
     "guidance": "All remote access paths should require MFA.",
     "evidence_hint": "VPN/RDP policy, authentication logs.",
     "severity_hint": "CRITICAL",
     "frameworks": {"NIST_CSF_2": "PR.AA-03", "ISO_27001": "A.9.4.2", "CIS_CONTROLS": "12.6"}},

    {"section": "IAM", "ref": "IAM-08", "text": "Are service accounts managed and inventoried?",
     "guidance": "Service accounts should be inventoried, have limited permissions, and rotated passwords.",
     "evidence_hint": "Service account inventory, password rotation records.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.AA-01", "ISO_27001": "A.9.2.1", "CIS_CONTROLS": "5.5"}},

    # --- BACKUP ---
    {"section": "BACKUP", "ref": "BKP-01", "text": "Are backups performed regularly (per documented schedule)?",
     "guidance": "Verify backup schedule aligns with RTO/RPO requirements.",
     "evidence_hint": "Backup schedule, backup logs/reports for last 30 days.",
     "severity_hint": "CRITICAL",
     "frameworks": {"NIST_CSF_2": "RC.RP-01", "ISO_27001": "A.12.3.1", "CIS_CONTROLS": "11.1"}},

    {"section": "BACKUP", "ref": "BKP-02", "text": "Are backups protected from ransomware (air-gapped, immutable, or offline)?",
     "guidance": "At least one backup copy should be isolated from the primary network.",
     "evidence_hint": "Backup architecture diagram, immutability settings.",
     "severity_hint": "CRITICAL",
     "frameworks": {"NIST_CSF_2": "RC.RP-05", "ISO_27001": "A.12.3.1", "CIS_CONTROLS": "11.4"}},

    {"section": "BACKUP", "ref": "BKP-03", "text": "Are backup restore tests performed regularly?",
     "guidance": "Backups are only valuable if restore has been verified. Min quarterly restore tests.",
     "evidence_hint": "Restore test records, test results for last 12 months.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "RC.RP-03", "ISO_27001": "A.12.3.1", "CIS_CONTROLS": "11.5"}},

    {"section": "BACKUP", "ref": "BKP-04", "text": "Is backup retention policy documented and followed?",
     "guidance": "Verify retention periods meet legal/regulatory and business requirements.",
     "evidence_hint": "Backup retention policy, backup repository configuration.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.DS-11", "ISO_27001": "A.12.3.1", "CIS_CONTROLS": "11.1"}},

    {"section": "BACKUP", "ref": "BKP-05", "text": "Are backup credentials and encryption keys stored securely?",
     "guidance": "Backup encryption keys should not be stored alongside backup data.",
     "evidence_hint": "Key management documentation, backup encryption configuration.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.DS-02", "ISO_27001": "A.10.1.1", "CIS_CONTROLS": "11.2"}},

    {"section": "BACKUP", "ref": "BKP-06", "text": "Does the backup scope cover all critical business systems?",
     "guidance": "Identify critical assets and verify all are included in backup scope.",
     "evidence_hint": "Critical asset list, backup scope documentation.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "RC.RP-01", "ISO_27001": "A.12.3.1", "CIS_CONTROLS": "11.1"}},

    # --- DLP ---
    {"section": "DLP", "ref": "DLP-01", "text": "Is sensitive data classified and labeled?",
     "guidance": "Verify existence of data classification policy and labeling implementation.",
     "evidence_hint": "Data classification policy, sample labeled documents/emails.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "ID.AM-05", "ISO_27001": "A.8.2.1", "DPDP_2023": "DPDP-8.5"}},

    {"section": "DLP", "ref": "DLP-02", "text": "Are external sharing channels (email/cloud) controlled for sensitive data?",
     "guidance": "Verify DLP policies that block or alert on sensitive data leaving the organization.",
     "evidence_hint": "DLP policy configuration, email gateway rules.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.DS-05", "ISO_27001": "A.13.2.1", "DPDP_2023": "DPDP-8.5"}},

    {"section": "DLP", "ref": "DLP-03", "text": "Are USB/removable media controls implemented?",
     "guidance": "Verify endpoint controls that restrict or monitor USB/removable storage.",
     "evidence_hint": "Endpoint DLP policy, device control policy.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.DS-05", "ISO_27001": "A.8.3.1", "CIS_CONTROLS": "13.7"}},

    {"section": "DLP", "ref": "DLP-04", "text": "Are source-code repositories access-controlled?",
     "guidance": "Verify RBAC on Git/SVN repositories. No public repositories for proprietary code.",
     "evidence_hint": "Repository access policy, GitLab/GitHub org settings.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.AA-05", "ISO_27001": "A.9.4.1", "CIS_CONTROLS": "4.7"}},

    {"section": "DLP", "ref": "DLP-05", "text": "Is a data retention and disposal policy implemented?",
     "guidance": "Verify formal data retention timelines and secure disposal procedures.",
     "evidence_hint": "Data retention policy, disposal records.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.DS-11", "ISO_27001": "A.8.3.2", "DPDP_2023": "DPDP-11.0"}},

    {"section": "DLP", "ref": "DLP-06", "text": "Is a personal data breach notification process defined?",
     "guidance": "Verify incident response includes personal data breach notification within 72 hours.",
     "evidence_hint": "Incident response policy, breach notification procedure.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "RS.CO-03", "DPDP_2023": "DPDP-8.6"}},

    # --- NETWORK ---
    {"section": "NETWORK", "ref": "NET-01", "text": "Are network segments separated for critical systems?",
     "guidance": "Verify network segmentation: separate VLANs for servers, endpoints, and management.",
     "evidence_hint": "Network diagram, VLAN/firewall configuration.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IR-01", "ISO_27001": "A.13.1.3", "CIS_CONTROLS": "12.2"}},

    {"section": "NETWORK", "ref": "NET-02", "text": "Is a next-generation firewall in use with defined rule sets?",
     "guidance": "Verify NGFW deployment and review firewall rule policy.",
     "evidence_hint": "Firewall model/version, rule export (sanitized), firewall policy.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IR-01", "ISO_27001": "A.13.1.1", "CIS_CONTROLS": "12.1"}},

    {"section": "NETWORK", "ref": "NET-03", "text": "Are unnecessary or high-risk ports blocked at the perimeter?",
     "guidance": "Verify that ports 23, 21, 139, 445, 3389 are not publicly exposed unnecessarily.",
     "evidence_hint": "Port scan results from external perspective.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IR-01", "ISO_27001": "A.13.1.1", "CIS_CONTROLS": "12.3"}},

    {"section": "NETWORK", "ref": "NET-04", "text": "Is network traffic monitored/logged for anomalies?",
     "guidance": "Verify network monitoring solution (SIEM, IDS/IPS, NetFlow) is operational.",
     "evidence_hint": "Network monitoring tool, sample alerts, SIEM configuration.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "DE.CM-01", "ISO_27001": "A.12.4.1", "CIS_CONTROLS": "13.6"}},

    {"section": "NETWORK", "ref": "NET-05", "text": "Is wireless network access secured appropriately?",
     "guidance": "Verify WPA3 or WPA2-Enterprise, guest network isolation, and MAC filtering.",
     "evidence_hint": "Wireless access policy, AP configuration.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.AA-03", "ISO_27001": "A.13.1.1", "CIS_CONTROLS": "12.4"}},

    # --- SERVERS ---
    {"section": "SERVERS", "ref": "SRV-01", "text": "Are server operating systems maintained with current security patches?",
     "guidance": "Verify patch management policy and patch compliance reports.",
     "evidence_hint": "Patch management reports, OS version details, WSUS/SCCM reports.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.MA-01", "ISO_27001": "A.12.6.1", "CIS_CONTROLS": "7.2"}},

    {"section": "SERVERS", "ref": "SRV-02", "text": "Are server hardening baselines applied?",
     "guidance": "Verify CIS benchmark or equivalent hardening baseline applied to servers.",
     "evidence_hint": "Hardening policy, CIS-CAT or equivalent scan results.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IP-01", "ISO_27001": "A.14.2.5", "CIS_CONTROLS": "4.1"}},

    {"section": "SERVERS", "ref": "SRV-03", "text": "Is antivirus/EDR deployed and actively monitoring on all servers?",
     "guidance": "Verify AV/EDR coverage: all servers should have an active endpoint security agent.",
     "evidence_hint": "EDR/AV management console report, coverage dashboard.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "DE.CM-04", "ISO_27001": "A.12.2.1", "CIS_CONTROLS": "10.1"}},

    {"section": "SERVERS", "ref": "SRV-04", "text": "Are server logs collected and retained centrally?",
     "guidance": "Verify centralized log management (SIEM/syslog) for all production servers.",
     "evidence_hint": "Log management solution, sample log entries, retention policy.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "DE.AE-03", "ISO_27001": "A.12.4.1", "CIS_CONTROLS": "8.2"}},

    # --- ENDPOINTS ---
    {"section": "ENDPOINTS", "ref": "EP-01", "text": "Is full disk encryption enabled on all workstations and laptops?",
     "guidance": "Verify BitLocker/FileVault or equivalent is enforced on all endpoints.",
     "evidence_hint": "Endpoint management console, encryption policy.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.DS-01", "ISO_27001": "A.10.1.1", "CIS_CONTROLS": "3.6"}},

    {"section": "ENDPOINTS", "ref": "EP-02", "text": "Is endpoint management/MDM solution deployed for all devices?",
     "guidance": "Verify MDM/Intune/JAMF covers all corporate endpoints.",
     "evidence_hint": "MDM coverage report, device inventory.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "ID.AM-01", "ISO_27001": "A.8.1.1", "CIS_CONTROLS": "1.1"}},

    {"section": "ENDPOINTS", "ref": "EP-03", "text": "Is a software allowlisting or application control policy in place?",
     "guidance": "Verify only approved software can execute on endpoints.",
     "evidence_hint": "Application control policy, AppLocker/WDAC configuration.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.IP-01", "ISO_27001": "A.12.5.1", "CIS_CONTROLS": "2.5"}},

    # --- WEB/DOMAIN/EMAIL ---
    {"section": "WEB_DOMAIN_EMAIL", "ref": "WEB-01", "text": "Are email security controls (SPF, DKIM, DMARC) configured?",
     "guidance": "Verify SPF, DKIM and DMARC TXT records are correctly configured for all domains.",
     "evidence_hint": "DNS record outputs: SPF, DKIM, DMARC.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IR-01", "CIS_CONTROLS": "9.4"}},

    {"section": "WEB_DOMAIN_EMAIL", "ref": "WEB-02", "text": "Do web applications use HTTPS with a valid, up-to-date TLS certificate?",
     "guidance": "Verify all public-facing web apps redirect HTTP to HTTPS with valid cert (no SHA-1, no TLS 1.1/1.0).",
     "evidence_hint": "TLS scan output, certificate details.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.DS-02", "ISO_27001": "A.10.1.1", "CIS_CONTROLS": "3.10"}},

    {"section": "WEB_DOMAIN_EMAIL", "ref": "WEB-03", "text": "Are security HTTP response headers implemented on web applications?",
     "guidance": "Verify: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
     "evidence_hint": "HTTP header scan output.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.IP-01", "ISO_27001": "A.14.1.2"}},

    {"section": "WEB_DOMAIN_EMAIL", "ref": "WEB-04", "text": "Is a Web Application Firewall (WAF) deployed for customer-facing applications?",
     "guidance": "Verify WAF deployment and active rule sets.",
     "evidence_hint": "WAF platform, active rule set configuration.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "PR.IR-01", "ISO_27001": "A.13.1.1", "CIS_CONTROLS": "16.9"}},

    # --- COMPLIANCE ---
    {"section": "COMPLIANCE", "ref": "COMP-01", "text": "Is an information security policy formally documented and approved?",
     "guidance": "Verify IS policy exists, is approved by management, and communicated to all staff.",
     "evidence_hint": "Information security policy document with sign-off.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "GV.PO-01", "ISO_27001": "A.5.1.1", "CIS_CONTROLS": "5.1"}},

    {"section": "COMPLIANCE", "ref": "COMP-02", "text": "Is a formal incident response plan documented and tested?",
     "guidance": "Verify IRP exists and was tested (tabletop or live exercise) within the last 12 months.",
     "evidence_hint": "Incident response plan, last test/exercise record.",
     "severity_hint": "HIGH",
     "frameworks": {"NIST_CSF_2": "RS.MA-01", "ISO_27001": "A.16.1.1", "CIS_CONTROLS": "17.1"}},

    {"section": "COMPLIANCE", "ref": "COMP-03", "text": "Is security awareness training provided to all employees?",
     "guidance": "Verify formal security awareness training program with records.",
     "evidence_hint": "Training platform records, completion rates, training materials.",
     "severity_hint": "MEDIUM",
     "frameworks": {"NIST_CSF_2": "PR.AT-01", "ISO_27001": "A.7.2.2", "CIS_CONTROLS": "14.1"}},
]

# DLP Control Areas
_DLP_CONTROL_AREAS = [
    "EMAIL",
    "USB_REMOVABLE_MEDIA",
    "CLOUD_FILE_SHARING",
    "BROWSER_UPLOADS",
    "GIT_SOURCE_CODE",
    "FILE_SHARES",
    "ENDPOINT_CONTROLS",
    "VPN_REMOTE_ACCESS",
    "ACCESS_CONTROL",
    "LOGGING_MONITORING",
    "DLP_POLICY",
]


# ---------------------------------------------------------------------------
# EngagementStore — Data Access Layer
# ---------------------------------------------------------------------------

class EngagementStore:
    """
    Data Access Layer for the SecureScope professional assessment lifecycle.

    Usage:
        store = EngagementStore()
        client_id = store.create_client("Acme Corp", industry="Manufacturing")
        engagement_id = store.create_engagement(client_id, "Q3 Security Assessment")
    """

    def __init__(self, db_path: str = "data/llm_audit.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_schema()
        self._seed_default_questions()

    # ------------------------------------------------------------------ #
    # Connection / Schema
    # ------------------------------------------------------------------ #

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _seed_default_questions(self) -> None:
        """Insert the built-in question bank if not already present."""
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT COUNT(*) FROM assessment_questions"
            ).fetchone()[0]
            if existing > 0:
                return
            now = _now_iso()
            for i, q in enumerate(_DEFAULT_QUESTIONS):
                conn.execute(
                    """INSERT INTO assessment_questions
                       (id, template_id, section, question_ref, question_text,
                        guidance, evidence_hint, severity_hint, framework_refs, order_index, is_active, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,1,?)""",
                    (
                        _new_id(), None,
                        q["section"], q["ref"], q["text"],
                        q.get("guidance"), q.get("evidence_hint"), q.get("severity_hint"),
                        json.dumps(q.get("frameworks", {})),
                        i, now,
                    ),
                )

    def _row_to_dict(self, row) -> dict | None:
        if row is None:
            return None
        return dict(row)

    def _rows_to_list(self, rows) -> list[dict]:
        return [dict(r) for r in rows]

    def _parse_json_field(self, value: str | None, default=None):
        if value is None:
            return default if default is not None else []
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return default if default is not None else []

    # ------------------------------------------------------------------ #
    # Audit Logging
    # ------------------------------------------------------------------ #

    def audit(
        self,
        actor: str,
        action: str,
        *,
        engagement_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        result: str = "SUCCESS",
        details: dict | None = None,
        ip_address: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO engagement_audit_log
                   (id, engagement_id, actor, action, object_type, object_id, result, details, ip_address, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    _new_id(), engagement_id, actor, action,
                    object_type, object_id, result,
                    json.dumps(details) if details else None,
                    ip_address, _now_iso(),
                ),
            )

    def list_audit_log(
        self,
        engagement_id: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        with self._connect() as conn:
            if engagement_id:
                rows = conn.execute(
                    "SELECT * FROM engagement_audit_log WHERE engagement_id=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (engagement_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM engagement_audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return self._rows_to_list(rows)

    # ------------------------------------------------------------------ #
    # Clients
    # ------------------------------------------------------------------ #

    def create_client(
        self,
        company_name: str,
        *,
        industry: str | None = None,
        location: str | None = None,
        contact_person: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        website: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> str:
        cid = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO clients
                   (id, company_name, industry, location, contact_person, email, phone, website, notes, created_by, created_at, updated_at, is_deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (cid, company_name, industry, location, contact_person, email, phone, website, notes, created_by, now, now),
            )
        return cid

    def get_client(self, client_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM clients WHERE id=? AND is_deleted=0", (client_id,)
            ).fetchone()
            return self._row_to_dict(row)

    def list_clients(self, org_id: str | None = None) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM clients WHERE is_deleted=0 ORDER BY company_name ASC"
            ).fetchall()
            return self._rows_to_list(rows)

    def update_client(self, client_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {"company_name", "industry", "location", "contact_person", "email", "phone", "website", "notes"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE clients SET {placeholders} WHERE id=? AND is_deleted=0",
                (*fields.values(), client_id),
            )
            return cur.rowcount > 0

    def delete_client(self, client_id: str) -> bool:
        """Soft delete."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE clients SET is_deleted=1, updated_at=? WHERE id=?",
                (_now_iso(), client_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Engagements
    # ------------------------------------------------------------------ #

    def create_engagement(
        self,
        client_id: str,
        assessment_name: str,
        *,
        assessment_type: str = "IT_SECURITY_ASSESSMENT",
        start_date: str | None = None,
        end_date: str | None = None,
        assessor: str | None = None,
        reviewer: str | None = None,
        scope_summary: str | None = None,
        methodology: str | None = None,
        notes: str | None = None,
        org_id: str | None = None,
        created_by: str | None = None,
    ) -> str:
        eid = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO engagements
                   (id, client_id, assessment_name, assessment_type, status, start_date, end_date,
                    assessor, reviewer, scope_summary, authorization_status, methodology, notes,
                    org_id, created_by, created_at, updated_at, is_deleted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (eid, client_id, assessment_name, assessment_type, "DRAFT",
                 start_date, end_date, assessor, reviewer, scope_summary,
                 "PENDING", methodology, notes, org_id, created_by, now, now),
            )
        return eid

    def get_engagement(self, engagement_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT e.*, c.company_name AS client_name, c.industry AS client_industry
                   FROM engagements e
                   LEFT JOIN clients c ON e.client_id = c.id
                   WHERE e.id=? AND e.is_deleted=0""",
                (engagement_id,),
            ).fetchone()
            return self._row_to_dict(row)

    def list_engagements(
        self,
        client_id: str | None = None,
        status: str | None = None,
        org_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        sql = """SELECT e.*, c.company_name AS client_name
                 FROM engagements e
                 LEFT JOIN clients c ON e.client_id = c.id
                 WHERE e.is_deleted=0"""
        params: list = []
        if client_id:
            sql += " AND e.client_id=?"
            params.append(client_id)
        if status:
            sql += " AND e.status=?"
            params.append(status)
        if org_id:
            sql += " AND e.org_id=?"
            params.append(org_id)
        sql += " ORDER BY e.created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def update_engagement(self, engagement_id: str, updates: dict) -> bool:
        allowed = {
            "assessment_name", "assessment_type", "status", "start_date", "end_date",
            "assessor", "reviewer", "scope_summary", "authorization_status",
            "authorization_document", "authorization_date", "authorized_by",
            "methodology", "notes",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        # Validate status transition if status is being updated
        if "status" in fields:
            new_status = fields["status"]
            if new_status not in ENGAGEMENT_STATES:
                return False
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE engagements SET {placeholders} WHERE id=? AND is_deleted=0",
                (*fields.values(), engagement_id),
            )
            return cur.rowcount > 0

    def advance_engagement_status(
        self,
        engagement_id: str,
        new_status: str,
        actor: str = "system",
    ) -> tuple[bool, str]:
        """
        Advance engagement to new_status.
        Enforces: AUTHORIZED or beyond required before allowing active scanning.
        Returns (success, message).
        """
        if new_status not in ENGAGEMENT_STATES:
            return False, f"Invalid status: {new_status}"
        eng = self.get_engagement(engagement_id)
        if not eng:
            return False, "Engagement not found"
        current_status = eng.get("status", "DRAFT")
        current_idx = ENGAGEMENT_STATES.index(current_status) if current_status in ENGAGEMENT_STATES else 0
        new_idx = ENGAGEMENT_STATES.index(new_status)
        # Allow moving forward or backward (assessors may need to revisit)
        ok = self.update_engagement(engagement_id, {"status": new_status})
        if ok:
            self.audit(
                actor, "ADVANCE_STATUS",
                engagement_id=engagement_id,
                object_type="ENGAGEMENT",
                object_id=engagement_id,
                details={"from": current_status, "to": new_status},
            )
        return ok, ("OK" if ok else "Update failed")

    def delete_engagement(self, engagement_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE engagements SET is_deleted=1, updated_at=? WHERE id=?",
                (_now_iso(), engagement_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Scope Validation
    # ------------------------------------------------------------------ #

    def validate_scope(self, engagement_id: str) -> tuple[bool, str]:
        """
        Verify the engagement is authorized and has scope defined.
        Returns (is_authorized, reason).
        """
        eng = self.get_engagement(engagement_id)
        if not eng:
            return False, "Engagement not found"
        if eng.get("status") == "DRAFT":
            return False, "Engagement is not yet authorized. Active scanning requires AUTHORIZED status or beyond."
        if eng.get("authorization_status") != "AUTHORIZED":
            return False, "Engagement has not been authorized. Obtain scope authorization before scanning."
        scope = self.list_scope(engagement_id)
        if not scope:
            return False, "No scope defined. Add scope entries before scanning."
        return True, "OK"

    def is_target_in_scope(self, engagement_id: str, target: str) -> bool:
        """
        Check if a target (hostname or IP) is within the engagement scope.
        Exclusions are evaluated first. If an exclusion matches, returns False.
        Then in-scope CIDRs, IPs, domains, and subnets are checked.
        """
        import ipaddress
        scope = self.list_scope(engagement_id)
        if not scope:
            return True

        target_clean = (target or "").strip().lower()
        if not target_clean:
            return False

        # Parse target IP if valid
        target_ip = None
        try:
            target_ip = ipaddress.ip_address(target_clean)
        except ValueError:
            pass

        # 1. Check EXCLUSIONS first
        for entry in scope:
            if not entry.get("excluded"):
                continue
            val = (entry.get("value") or "").strip().lower()
            if not val:
                continue
            if val == target_clean:
                return False
            if target_ip:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if target_ip in net:
                        return False
                except ValueError:
                    pass
            elif val in target_clean:
                return False

        # 2. Check INCLUSIONS
        for entry in scope:
            if entry.get("excluded"):
                continue
            val = (entry.get("value") or "").strip().lower()
            if not val:
                continue
            if target_ip:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if target_ip in net:
                        return True
                except ValueError:
                    pass
            # Domain or hostname match
            if val == target_clean or target_clean.endswith("." + val) or val.endswith("." + target_clean):
                return True
            if val in target_clean:
                return True

        return False

    def add_scope_entry(
        self,
        engagement_id: str,
        scope_type: str,
        value: str,
        *,
        description: str | None = None,
        excluded: bool = False,
    ) -> str:
        sid = _new_id()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO engagement_scope (id, engagement_id, scope_type, value, description, excluded, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (sid, engagement_id, scope_type, value, description, int(excluded), _now_iso()),
            )
        return sid

    def list_scope(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM engagement_scope WHERE engagement_id=? ORDER BY excluded ASC, scope_type ASC",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def delete_scope_entry(self, scope_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM engagement_scope WHERE id=?", (scope_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Engagement Assets
    # ------------------------------------------------------------------ #

    def add_asset(
        self,
        engagement_id: str,
        *,
        asset_id: str | None = None,
        asset_type: str | None = None,
        hostname: str | None = None,
        ip_address: str | None = None,
        os: str | None = None,
        criticality: str = "MEDIUM",
        data_sensitivity: str = "INTERNAL",
        include_in_assessment: bool = True,
        assessment_notes: str | None = None,
    ) -> str:
        aid = _new_id()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO eng_assets
                   (id, engagement_id, asset_id, asset_type, hostname, ip_address, os,
                    criticality, data_sensitivity, include_in_assessment, assessment_notes, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (aid, engagement_id, asset_id, asset_type, hostname, ip_address, os,
                 criticality.upper(), data_sensitivity.upper(),
                 int(include_in_assessment), assessment_notes, _now_iso()),
            )
        return aid

    def list_assets(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM eng_assets WHERE engagement_id=? ORDER BY asset_type, hostname",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_asset(self, asset_id: str, updates: dict) -> bool:
        allowed = {"criticality", "data_sensitivity", "include_in_assessment", "assessment_notes", "os", "hostname", "ip_address"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE eng_assets SET {placeholders} WHERE id=?",
                (*fields.values(), asset_id),
            )
            return cur.rowcount > 0

    def delete_asset(self, asset_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM eng_assets WHERE id=?", (asset_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Assessment Questions
    # ------------------------------------------------------------------ #

    def list_questions(
        self,
        section: str | None = None,
        template_id: str | None = None,
    ) -> list[dict]:
        sql = "SELECT * FROM assessment_questions WHERE is_active=1"
        params: list = []
        if section:
            sql += " AND section=?"
            params.append(section.upper())
        if template_id:
            sql += " AND (template_id=? OR template_id IS NULL)"
            params.append(template_id)
        sql += " ORDER BY section, order_index"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def get_question(self, question_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assessment_questions WHERE id=?", (question_id,)
            ).fetchone()
            return self._row_to_dict(row)

    # ------------------------------------------------------------------ #
    # Assessment Responses
    # ------------------------------------------------------------------ #

    def get_or_create_response(self, engagement_id: str, question_id: str) -> dict:
        """Get existing response or create a blank NOT_ASSESSED one."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assessment_responses WHERE engagement_id=? AND question_id=?",
                (engagement_id, question_id),
            ).fetchone()
            if row:
                return self._row_to_dict(row)
            q = self.get_question(question_id)
            section = q.get("section", "GENERAL") if q else "GENERAL"
            rid = _new_id()
            now = _now_iso()
            conn.execute(
                """INSERT INTO assessment_responses
                   (id, engagement_id, question_id, section, status, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (rid, engagement_id, question_id, section, "NOT_ASSESSED", now),
            )
            return {"id": rid, "engagement_id": engagement_id, "question_id": question_id,
                    "section": section, "status": "NOT_ASSESSED", "updated_at": now}

    def update_response(self, response_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {
            "status", "response_text", "observation", "recommendation", "risk_note",
            "evidence_ids", "finding_ids", "reviewed_by", "assessed_by", "assessed_at",
            "is_not_applicable", "na_reason",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "status" in fields and fields["status"] not in RESPONSE_STATUSES:
            return False
        # JSON serialize list fields
        for json_field in ("evidence_ids", "finding_ids"):
            if json_field in fields and isinstance(fields[json_field], list):
                fields[json_field] = json.dumps(fields[json_field])
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE assessment_responses SET {placeholders} WHERE id=?",
                (*fields.values(), response_id),
            )
            return cur.rowcount > 0

    def list_responses(
        self,
        engagement_id: str,
        section: str | None = None,
    ) -> list[dict]:
        sql = """SELECT r.*, q.question_ref, q.question_text, q.section AS q_section,
                        q.severity_hint, q.framework_refs
                 FROM assessment_responses r
                 LEFT JOIN assessment_questions q ON r.question_id = q.id
                 WHERE r.engagement_id=?"""
        params: list = [engagement_id]
        if section:
            sql += " AND r.section=?"
            params.append(section.upper())
        sql += " ORDER BY q.order_index"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def get_section_status(self, engagement_id: str, section: str) -> dict:
        """Compute section completion stats."""
        responses = self.list_responses(engagement_id, section)
        if not responses:
            return {"section": section, "status": "NOT_STARTED", "total": 0, "assessed": 0, "passed": 0, "failed": 0, "partial": 0, "not_applicable": 0, "not_assessed": 0}
        total = len(responses)
        counts = {s: 0 for s in RESPONSE_STATUSES}
        for r in responses:
            counts[r.get("status", "NOT_ASSESSED")] += 1
        assessed = total - counts["NOT_ASSESSED"]
        if assessed == 0:
            status = "NOT_STARTED"
        elif assessed == total:
            status = "COMPLETED"
        else:
            status = "IN_PROGRESS"
        return {
            "section": section,
            "status": status,
            "total": total,
            "assessed": assessed,
            "passed": counts["PASS"],
            "partial": counts["PARTIAL"],
            "failed": counts["FAIL"],
            "not_applicable": counts["NOT_APPLICABLE"],
            "not_assessed": counts["NOT_ASSESSED"],
        }

    def get_assessment_overview(self, engagement_id: str) -> dict:
        """Return a full progress overview for the engagement overview page."""
        sections = {}
        for section in ASSESSMENT_SECTIONS:
            sections[section] = self.get_section_status(engagement_id, section)
        findings = self.list_findings(engagement_id)
        severity_counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]}
        status_counts = {s: 0 for s in FINDING_STATUSES}
        for f in findings:
            sev = (f.get("severity") or "LOW").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            st = (f.get("status") or "OPEN").upper()
            if st in status_counts:
                status_counts[st] += 1
        remediated = sum(1 for f in findings if f.get("status") in ("RESOLVED", "RISK_ACCEPTED"))
        remediation_rate = int((remediated / max(1, len(findings))) * 100) if findings else 0
        retested = sum(1 for f in findings if f.get("retest_status") in ("PASS", "PARTIAL", "FAIL"))
        risk_register = self.get_risk_summary(engagement_id)
        return {
            "sections": sections,
            "findings": {
                "total": len(findings),
                "by_severity": severity_counts,
                "by_status": status_counts,
                "remediation_rate": remediation_rate,
                "retested": retested,
            },
            "risk": risk_register,
        }

    # ------------------------------------------------------------------ #
    # Findings
    # ------------------------------------------------------------------ #

    def _auto_finding_ref(self, engagement_id: str) -> str:
        with self._connect() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE engagement_id=?", (engagement_id,)
            ).fetchone()[0]
        return f"F-{n + 1:03d}"

    def create_finding(
        self,
        engagement_id: str,
        section: str,
        title: str,
        description: str,
        severity: str,
        *,
        question_id: str | None = None,
        category: str | None = None,
        affected_asset: str | None = None,
        asset_id: str | None = None,
        likelihood: str = "MEDIUM",
        impact: str = "MEDIUM",
        asset_criticality: str | None = None,
        data_sensitivity: str | None = None,
        existing_controls: str | None = None,
        controls_mitigate: bool = False,
        business_impact: str | None = None,
        technical_impact: str | None = None,
        recommendation: str | None = None,
        remediation_guidance: str | None = None,
        retest_requirement: str | None = None,
        reference: str | None = None,
        framework_refs: dict | None = None,
        owner: str | None = None,
        due_date: str | None = None,
        created_by: str | None = None,
        is_demo: bool = False,
    ) -> str:
        fid = _new_id()
        now = _now_iso()
        ref = self._auto_finding_ref(engagement_id)
        # Calculate risk priority automatically
        crit = asset_criticality or "MEDIUM"
        sens = data_sensitivity or "INTERNAL"
        score, priority = calculate_risk_priority(
            severity, likelihood, impact, crit, sens, controls_mitigate
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO findings
                   (id, engagement_id, section, question_id, finding_ref, title, category,
                    description, affected_asset, asset_id, severity, likelihood, impact,
                    asset_criticality, data_sensitivity, existing_controls, controls_mitigate,
                    risk_score, risk_priority, business_impact, technical_impact,
                    recommendation, remediation_guidance, retest_requirement, reference,
                    framework_refs, owner, status, remediation_status, retest_status,
                    due_date, is_demo, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fid, engagement_id, section.upper(), question_id, ref, title, category,
                    description, affected_asset, asset_id, severity.upper(), likelihood.upper(), impact.upper(),
                    crit.upper(), sens.upper(), existing_controls, int(controls_mitigate),
                    score, priority, business_impact, technical_impact,
                    recommendation, remediation_guidance, retest_requirement, reference,
                    json.dumps(framework_refs) if framework_refs else None,
                    owner, "OPEN", "NOT_STARTED", "PENDING",
                    due_date, int(is_demo), created_by, now, now,
                ),
            )
        return fid

    def get_finding(self, finding_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            return self._row_to_dict(row)

    def list_findings(
        self,
        engagement_id: str,
        section: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        sql = "SELECT * FROM findings WHERE engagement_id=?"
        params: list = [engagement_id]
        if section:
            sql += " AND section=?"
            params.append(section.upper())
        if severity:
            sql += " AND severity=?"
            params.append(severity.upper())
        if status:
            sql += " AND status=?"
            params.append(status.upper())
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def update_finding(self, finding_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {
            "title", "category", "description", "affected_asset", "severity", "likelihood", "impact",
            "asset_criticality", "data_sensitivity", "existing_controls", "controls_mitigate",
            "business_impact", "technical_impact", "recommendation", "remediation_guidance",
            "retest_requirement", "reference", "framework_refs", "owner", "status",
            "remediation_status", "retest_status", "due_date", "closed_at", "closed_by",
            "risk_priority_override", "risk_override_justification",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "status" in fields and fields["status"] not in FINDING_STATUSES:
            return False
        if "risk_priority_override" in fields and "risk_override_justification" not in fields:
            # Justification is required if override is changing
            pass  # Caller is responsible; we still allow it for pre-validated calls
        # Recalculate risk if severity/likelihood/impact changed
        if any(k in fields for k in ("severity", "likelihood", "impact", "asset_criticality", "data_sensitivity", "controls_mitigate")):
            f = self.get_finding(finding_id)
            if f:
                sev = fields.get("severity", f.get("severity", "MEDIUM"))
                lik = fields.get("likelihood", f.get("likelihood", "MEDIUM"))
                imp = fields.get("impact", f.get("impact", "MEDIUM"))
                crit = fields.get("asset_criticality", f.get("asset_criticality", "MEDIUM"))
                sens = fields.get("data_sensitivity", f.get("data_sensitivity", "INTERNAL"))
                mit = bool(fields.get("controls_mitigate", f.get("controls_mitigate", False)))
                score, priority = calculate_risk_priority(sev, lik, imp, crit, sens, mit)
                fields["risk_score"] = score
                fields["risk_priority"] = priority
        if "framework_refs" in fields and isinstance(fields["framework_refs"], dict):
            fields["framework_refs"] = json.dumps(fields["framework_refs"])
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE findings SET {placeholders} WHERE id=?",
                (*fields.values(), finding_id),
            )
            # Sync risk register entry if it exists
            if "status" in fields:
                conn.execute(
                    "UPDATE risk_register SET status=?, updated_at=? WHERE finding_id=?",
                    (fields["status"], _now_iso(), finding_id),
                )
            return cur.rowcount > 0

    def import_scan_finding(
        self,
        engagement_id: str,
        check: dict,
        section: str = "VULNERABILITY_ASSESSMENT",
        affected_asset: str | None = None,
        created_by: str | None = None,
    ) -> str | None:
        """Import a finding from scanner output (stored_scan_results check dict)."""
        if check.get("status") not in ("FAIL", "WARNING"):
            return None
        sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        severity = sev_map.get((check.get("severity") or "low").lower(), "MEDIUM")
        return self.create_finding(
            engagement_id, section,
            title=check.get("check", "Unknown Finding"),
            description=check.get("details", "No details provided."),
            severity=severity,
            affected_asset=affected_asset or check.get("target"),
            category=check.get("category"),
            recommendation=check.get("remediation"),
            reference=", ".join(check.get("frameworks", []) or []),
            created_by=created_by,
        )

    # ------------------------------------------------------------------ #
    # Evidence
    # ------------------------------------------------------------------ #

    def add_evidence(
        self,
        engagement_id: str,
        description: str,
        collected_by: str,
        evidence_type: str = "OTHER",
        *,
        finding_id: str | None = None,
        question_id: str | None = None,
        source: str | None = None,
        file_path: str | None = None,
        file_name: str | None = None,
        file_size: int | None = None,
        sensitivity: str = "CONFIDENTIAL",
        retention_days: int = 2555,
        notes: str | None = None,
    ) -> str:
        eid = _new_id()
        sha256 = None
        # Store evidence files under data/evidence/<engagement_id>/
        if file_path and os.path.exists(file_path):
            try:
                sha256 = _sha256_file(file_path)
            except Exception:
                sha256 = None
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO evidence
                   (id, engagement_id, finding_id, question_id, evidence_type, description, source,
                    collected_by, collected_at, sha256, file_path, file_name, file_size,
                    sensitivity, retention_days, notes, is_deleted, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)""",
                (eid, engagement_id, finding_id, question_id, evidence_type.upper(), description, source,
                 collected_by, _now_iso(), sha256, file_path, file_name, file_size,
                 sensitivity.upper(), retention_days, notes, _now_iso()),
            )
        return eid

    def get_evidence(self, evidence_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id=? AND is_deleted=0", (evidence_id,)
            ).fetchone()
            return self._row_to_dict(row)

    def list_evidence(
        self,
        engagement_id: str,
        finding_id: str | None = None,
        question_id: str | None = None,
    ) -> list[dict]:
        sql = "SELECT * FROM evidence WHERE engagement_id=? AND is_deleted=0"
        params: list = [engagement_id]
        if finding_id:
            sql += " AND finding_id=?"
            params.append(finding_id)
        if question_id:
            sql += " AND question_id=?"
            params.append(question_id)
        sql += " ORDER BY collected_at DESC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def delete_evidence(self, evidence_id: str, soft: bool = True) -> bool:
        with self._connect() as conn:
            if soft:
                cur = conn.execute(
                    "UPDATE evidence SET is_deleted=1 WHERE id=?", (evidence_id,)
                )
            else:
                cur = conn.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # DLP — Data Discovery
    # ------------------------------------------------------------------ #

    def add_dlp_data_record(
        self,
        engagement_id: str,
        data_type: str,
        sensitivity: str,
        location: str,
        *,
        owner: str | None = None,
        access_level: str | None = None,
        estimated_volume: str | None = None,
        format: str | None = None,
        classification_applied: bool = False,
        controls_applied: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> str:
        did = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO dlp_data_discovery
                   (id, engagement_id, data_type, sensitivity, location, owner, access_level,
                    estimated_volume, format, classification_applied, controls_applied, notes, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (did, engagement_id, data_type, sensitivity.upper(), location, owner, access_level,
                 estimated_volume, format, int(classification_applied), controls_applied, notes, created_by, now, now),
            )
        return did

    def list_dlp_data_records(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dlp_data_discovery WHERE engagement_id=? ORDER BY sensitivity DESC",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_dlp_data_record(self, record_id: str, updates: dict) -> bool:
        allowed = {"data_type", "sensitivity", "location", "owner", "access_level",
                   "estimated_volume", "format", "classification_applied", "controls_applied", "notes"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE dlp_data_discovery SET {placeholders} WHERE id=?",
                (*fields.values(), record_id),
            )
            return cur.rowcount > 0

    def delete_dlp_data_record(self, record_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM dlp_data_discovery WHERE id=?", (record_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # DLP — Data Flows
    # ------------------------------------------------------------------ #

    def add_data_flow(
        self,
        engagement_id: str,
        source: str,
        destination: str,
        data_type: str,
        channel: str,
        *,
        sensitivity: str = "CONFIDENTIAL",
        user_role: str | None = None,
        security_control: str | None = None,
        risk_level: str | None = None,
        observation: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> str:
        fid = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO dlp_data_flows
                   (id, engagement_id, source, destination, data_type, sensitivity, user_role,
                    channel, security_control, risk_level, observation, notes, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, engagement_id, source, destination, data_type, sensitivity.upper(), user_role,
                 channel.upper(), security_control, risk_level, observation, notes, created_by, now, now),
            )
        return fid

    def list_data_flows(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dlp_data_flows WHERE engagement_id=? ORDER BY risk_level DESC, source",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_data_flow(self, flow_id: str, updates: dict) -> bool:
        allowed = {"source", "destination", "data_type", "sensitivity", "user_role",
                   "channel", "security_control", "risk_level", "observation", "notes"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE dlp_data_flows SET {placeholders} WHERE id=?",
                (*fields.values(), flow_id),
            )
            return cur.rowcount > 0

    def delete_data_flow(self, flow_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM dlp_data_flows WHERE id=?", (flow_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # DLP — Security Controls
    # ------------------------------------------------------------------ #

    def initialize_dlp_controls(self, engagement_id: str) -> None:
        """Create default NOT_ASSESSED entries for all DLP control areas."""
        now = _now_iso()
        with self._connect() as conn:
            for area in _DLP_CONTROL_AREAS:
                existing = conn.execute(
                    "SELECT id FROM dlp_controls WHERE engagement_id=? AND control_area=?",
                    (engagement_id, area),
                ).fetchone()
                if not existing:
                    conn.execute(
                        """INSERT INTO dlp_controls
                           (id, engagement_id, control_area, status, updated_at)
                           VALUES (?,?,?,?,?)""",
                        (_new_id(), engagement_id, area, "NOT_ASSESSED", now),
                    )

    def list_dlp_controls(self, engagement_id: str) -> list[dict]:
        self.initialize_dlp_controls(engagement_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dlp_controls WHERE engagement_id=? ORDER BY control_area",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_dlp_control(self, control_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {"status", "observation", "recommendation", "evidence_ids", "risk_level", "assessed_by", "assessed_at"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "status" in fields and fields["status"] not in RESPONSE_STATUSES + ["NOT_ASSESSED"]:
            return False
        if "evidence_ids" in fields and isinstance(fields["evidence_ids"], list):
            fields["evidence_ids"] = json.dumps(fields["evidence_ids"])
        fields["updated_at"] = _now_iso()
        if not fields.get("assessed_at") and "status" in fields and fields["status"] != "NOT_ASSESSED":
            fields["assessed_at"] = _now_iso()
        if not fields.get("assessed_by") and actor != "system":
            fields["assessed_by"] = actor
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE dlp_controls SET {placeholders} WHERE id=?",
                (*fields.values(), control_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # DLP — Controlled Validation
    # ------------------------------------------------------------------ #

    def add_dlp_validation(
        self,
        engagement_id: str,
        channel: str,
        test_objective: str,
        test_data_id: str,
        expected_result: str,
        *,
        date_tested: str | None = None,
        tested_by: str | None = None,
        actual_result: str | None = None,
        status: str = "NOT_TESTED",
        evidence_ids: list | None = None,
        notes: str | None = None,
    ) -> str:
        vid = _new_id()
        now = _now_iso()
        # Auto-generate validation ref
        with self._connect() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM dlp_validations WHERE engagement_id=?", (engagement_id,)
            ).fetchone()[0]
            ref = f"DLP-VAL-{n + 1:03d}"
            conn.execute(
                """INSERT INTO dlp_validations
                   (id, engagement_id, validation_ref, channel, test_objective, test_data_id,
                    date_tested, tested_by, expected_result, actual_result, status, evidence_ids, notes, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (vid, engagement_id, ref, channel.upper(), test_objective, test_data_id,
                 date_tested, tested_by, expected_result, actual_result, status.upper(),
                 json.dumps(evidence_ids or []), notes, now, now),
            )
        return vid

    def list_dlp_validations(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dlp_validations WHERE engagement_id=? ORDER BY created_at",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_dlp_validation(self, validation_id: str, updates: dict) -> bool:
        allowed = {"actual_result", "status", "date_tested", "tested_by", "evidence_ids", "notes", "test_objective", "expected_result"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "evidence_ids" in fields and isinstance(fields["evidence_ids"], list):
            fields["evidence_ids"] = json.dumps(fields["evidence_ids"])
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE dlp_validations SET {placeholders} WHERE id=?",
                (*fields.values(), validation_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Risk Register
    # ------------------------------------------------------------------ #

    def get_risk_summary(self, engagement_id: str) -> dict:
        """High-level risk summary for the overview dashboard."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT risk_priority, status FROM risk_register WHERE engagement_id=?",
                (engagement_id,),
            ).fetchall()
        if not rows:
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0, "closed": 0}
        total = len(rows)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        open_count = 0
        closed_count = 0
        for r in rows:
            pri = (r["risk_priority"] or "LOW").upper()
            if pri in counts:
                counts[pri] += 1
            if (r["status"] or "OPEN").upper() in ("OPEN", "IN_PROGRESS"):
                open_count += 1
            else:
                closed_count += 1
        return {
            "total": total,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "open": open_count,
            "closed": closed_count,
        }

    def sync_findings_to_risk_register(self, engagement_id: str) -> int:
        """Sync all findings into the risk register. Returns count of new entries created."""
        findings = self.list_findings(engagement_id)
        now = _now_iso()
        created = 0
        with self._connect() as conn:
            n_base = conn.execute(
                "SELECT COUNT(*) FROM risk_register WHERE engagement_id=?", (engagement_id,)
            ).fetchone()[0]
            for f in findings:
                existing = conn.execute(
                    "SELECT id FROM risk_register WHERE finding_id=?", (f["id"],)
                ).fetchone()
                if existing:
                    # Update priority if it has changed
                    conn.execute(
                        """UPDATE risk_register
                           SET risk_priority=?, risk_score=?, severity=?, status=?, updated_at=?
                           WHERE finding_id=?""",
                        (f.get("risk_priority_override") or f.get("risk_priority"),
                         f.get("risk_score"), f.get("severity"),
                         f.get("status"), now, f["id"]),
                    )
                else:
                    ref = f"RR-{n_base + created + 1:03d}"
                    conn.execute(
                        """INSERT INTO risk_register
                           (id, engagement_id, finding_id, risk_ref, category, asset, title,
                            description, severity, likelihood, impact, risk_score, risk_priority,
                            evidence_ids, recommendation, owner, due_date, status, retest_status,
                            framework_refs, created_by, created_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (_new_id(), engagement_id, f["id"], ref,
                         f.get("category"), f.get("affected_asset"), f.get("title"),
                         f.get("description"), f.get("severity"), f.get("likelihood"), f.get("impact"),
                         f.get("risk_score"), f.get("risk_priority_override") or f.get("risk_priority"),
                         f.get("evidence_ids"), f.get("recommendation"),
                         f.get("owner"), f.get("due_date"), f.get("status"), f.get("retest_status"),
                         f.get("framework_refs"), f.get("created_by"), now, now),
                    )
                    created += 1
        return created

    def list_risk_register(
        self,
        engagement_id: str,
        status: str | None = None,
        priority: str | None = None,
    ) -> list[dict]:
        sql = "SELECT * FROM risk_register WHERE engagement_id=?"
        params: list = [engagement_id]
        if status:
            sql += " AND status=?"
            params.append(status.upper())
        if priority:
            sql += " AND risk_priority=?"
            params.append(priority.upper())
        sql += """ ORDER BY
            CASE risk_priority WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
            created_at ASC"""
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def update_risk_register_entry(self, entry_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {
            "risk_priority_override", "risk_override_justification", "treatment",
            "owner", "due_date", "status", "notes", "recommendation",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        # Require justification if overriding priority
        if "risk_priority_override" in fields and not fields.get("risk_override_justification"):
            fields.setdefault("risk_override_justification", "Override by assessor (no justification provided)")
        fields["updated_at"] = _now_iso()
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE risk_register SET {placeholders} WHERE id=?",
                (*fields.values(), entry_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Remediation
    # ------------------------------------------------------------------ #

    def add_remediation_action(
        self,
        finding_id: str,
        engagement_id: str,
        action_taken: str,
        *,
        assigned_to: str | None = None,
        target_date: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
    ) -> str:
        rid = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO remediation_actions
                   (id, finding_id, engagement_id, action_taken, assigned_to, target_date,
                    status, notes, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, finding_id, engagement_id, action_taken, assigned_to, target_date,
                 "NOT_STARTED", notes, created_by, now, now),
            )
        # Update finding remediation_status
        self.update_finding(finding_id, {"remediation_status": "IN_PROGRESS"}, actor=created_by or "system")
        return rid

    def list_remediation_actions(
        self,
        engagement_id: str | None = None,
        finding_id: str | None = None,
    ) -> list[dict]:
        sql = "SELECT r.*, f.title AS finding_title, f.severity AS finding_severity FROM remediation_actions r LEFT JOIN findings f ON r.finding_id = f.id WHERE 1=1"
        params: list = []
        if engagement_id:
            sql += " AND r.engagement_id=?"
            params.append(engagement_id)
        if finding_id:
            sql += " AND r.finding_id=?"
            params.append(finding_id)
        sql += " ORDER BY r.target_date ASC, r.created_at ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return self._rows_to_list(rows)

    def update_remediation_action(self, action_id: str, updates: dict, actor: str = "system") -> bool:
        allowed = {"status", "action_taken", "assigned_to", "target_date", "completed_date",
                   "evidence_path", "evidence_ids", "verified_by", "verified_at", "notes"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "evidence_ids" in fields and isinstance(fields["evidence_ids"], list):
            fields["evidence_ids"] = json.dumps(fields["evidence_ids"])
        fields["updated_at"] = _now_iso()
        with self._connect() as conn:
            placeholders = ", ".join(f"{k}=?" for k in fields)
            cur = conn.execute(
                f"UPDATE remediation_actions SET {placeholders} WHERE id=?",
                (*fields.values(), action_id),
            )
            if "status" in fields and fields["status"] == "COMPLETED":
                # Update finding remediation_status to READY_FOR_RETEST
                row = conn.execute(
                    "SELECT finding_id FROM remediation_actions WHERE id=?", (action_id,)
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE findings SET remediation_status='COMPLETED', status='READY_FOR_RETEST', updated_at=? WHERE id=?",
                        (_now_iso(), row["finding_id"]),
                    )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Retests
    # ------------------------------------------------------------------ #

    def create_retest(
        self,
        finding_id: str,
        engagement_id: str,
        *,
        original_finding_summary: str | None = None,
        remediation_summary: str | None = None,
        retest_by: str | None = None,
        retest_date: str | None = None,
        notes: str | None = None,
    ) -> str:
        rid = _new_id()
        now = _now_iso()
        with self._connect() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM retests WHERE engagement_id=?", (engagement_id,)
            ).fetchone()[0]
            ref = f"RT-{n + 1:03d}"
            conn.execute(
                """INSERT INTO retests
                   (id, finding_id, engagement_id, retest_ref, original_finding_summary, remediation_summary,
                    retest_by, retest_date, result, notes, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, finding_id, engagement_id, ref, original_finding_summary, remediation_summary,
                 retest_by, retest_date, "NOT_RETESTED", notes, now, now),
            )
        # Update finding status to RETESTED (pending result)
        self.update_finding(finding_id, {"status": "RETESTED", "retest_status": "IN_PROGRESS"})
        return rid

    def list_retests(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT r.*, f.title AS finding_title, f.severity AS finding_severity
                   FROM retests r
                   LEFT JOIN findings f ON r.finding_id = f.id
                   WHERE r.engagement_id=?
                   ORDER BY r.retest_date DESC""",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def update_retest(self, retest_id: str, updates: dict) -> bool:
        allowed = {"result", "retest_date", "retest_by", "remediation_summary",
                   "original_evidence_ids", "remediation_evidence_ids", "retest_evidence_ids", "notes"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        for json_field in ("original_evidence_ids", "remediation_evidence_ids", "retest_evidence_ids"):
            if json_field in fields and isinstance(fields[json_field], list):
                fields[json_field] = json.dumps(fields[json_field])
        fields["updated_at"] = _now_iso()
        with self._connect() as conn:
            placeholders = ", ".join(f"{k}=?" for k in fields)
            cur = conn.execute(
                f"UPDATE retests SET {placeholders} WHERE id=?",
                (*fields.values(), retest_id),
            )
            # Sync finding status if result is set
            if "result" in fields and fields["result"] in ("REMEDIATED", "NOT_REMEDIATED", "PARTIAL"):
                row = conn.execute(
                    "SELECT finding_id FROM retests WHERE id=?", (retest_id,)
                ).fetchone()
                if row:
                    new_status = "RESOLVED" if fields["result"] == "REMEDIATED" else "IN_PROGRESS"
                    new_retest = fields["result"]
                    conn.execute(
                        "UPDATE findings SET status=?, retest_status=?, updated_at=? WHERE id=?",
                        (new_status, new_retest, _now_iso(), row["finding_id"]),
                    )
                    # Sync risk register
                    conn.execute(
                        "UPDATE risk_register SET status=?, retest_status=?, updated_at=? WHERE finding_id=?",
                        (new_status, new_retest, _now_iso(), row["finding_id"]),
                    )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Reports
    # ------------------------------------------------------------------ #

    def _auto_document_id(self, engagement_id: str, report_type: str) -> str:
        import time
        year = datetime.now().year
        with self._connect() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM assessment_reports WHERE engagement_id=?", (engagement_id,)
            ).fetchone()[0]
        return f"RPT-{year}-{n + 1:04d}"

    def create_report_record(
        self,
        engagement_id: str,
        report_type: str,
        title: str,
        generated_by: str,
        *,
        reviewer: str | None = None,
        format: str = "HTML",
        file_path: str | None = None,
        classification: str = "CONFIDENTIAL",
        notes: str | None = None,
        version: str = "1.0",
    ) -> str:
        rid = _new_id()
        doc_id = self._auto_document_id(engagement_id, report_type)
        now = _now_iso()
        sha256 = None
        if file_path and os.path.exists(file_path):
            try:
                sha256 = _sha256_file(file_path)
            except Exception:
                pass
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO assessment_reports
                   (id, engagement_id, document_id, report_type, version, title, generated_by, reviewed_by,
                    generated_at, updated_at, format, file_path, sha256, status, classification, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, engagement_id, doc_id, report_type.upper(), version, title, generated_by, reviewer,
                 now, now, format.upper(), file_path, sha256, "DRAFT", classification.upper(), notes),
            )
        return rid

    def list_reports(self, engagement_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM assessment_reports WHERE engagement_id=? ORDER BY generated_at DESC",
                (engagement_id,),
            ).fetchall()
            return self._rows_to_list(rows)

    def finalize_report(self, report_id: str, reviewed_by: str | None = None) -> bool:
        fields = {"status": "FINAL", "updated_at": _now_iso()}
        if reviewed_by:
            fields["reviewed_by"] = reviewed_by
        placeholders = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE assessment_reports SET {placeholders} WHERE id=?",
                (*fields.values(), report_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Report Data Builders
    # ------------------------------------------------------------------ #

    def build_executive_report_data(self, engagement_id: str) -> dict:
        """Build the data dictionary for the executive report."""
        eng = self.get_engagement(engagement_id)
        if not eng:
            return {"error": "Engagement not found"}
        findings = self.list_findings(engagement_id)
        risk_register = self.list_risk_register(engagement_id)
        retests = self.list_retests(engagement_id)
        assets = self.list_assets(engagement_id)
        dlp_controls = self.list_dlp_controls(engagement_id)
        iam_responses = self.list_responses(engagement_id, "IAM")
        backup_responses = self.list_responses(engagement_id, "BACKUP")
        overview = self.get_assessment_overview(engagement_id)
        # Build 30/60/90 remediation roadmap
        from datetime import timedelta
        today = datetime.now().date()
        roadmap = {"30_days": [], "60_days": [], "90_days": []}
        for f in findings:
            if f.get("status") in ("RESOLVED", "RISK_ACCEPTED"):
                continue
            sev = (f.get("severity") or "LOW").upper()
            if sev in ("CRITICAL",):
                roadmap["30_days"].append(f.get("title"))
            elif sev in ("HIGH",):
                roadmap["60_days"].append(f.get("title"))
            else:
                roadmap["90_days"].append(f.get("title"))
        return {
            "engagement": eng,
            "generated_at": _now_iso(),
            "findings": {
                "all": findings,
                "critical": [f for f in findings if f.get("severity", "").upper() == "CRITICAL"],
                "high": [f for f in findings if f.get("severity", "").upper() == "HIGH"],
                "total": len(findings),
                "open": len([f for f in findings if f.get("status") not in ("RESOLVED", "RISK_ACCEPTED")]),
                "resolved": len([f for f in findings if f.get("status") == "RESOLVED"]),
            },
            "risk_register": risk_register,
            "risk_summary": self.get_risk_summary(engagement_id),
            "overview": overview,
            "assets": assets,
            "dlp_controls": dlp_controls,
            "iam_responses": iam_responses,
            "backup_responses": backup_responses,
            "retests": retests,
            "remediation_roadmap": roadmap,
        }

    def build_technical_report_data(self, engagement_id: str) -> dict:
        """Build the data dictionary for the technical report."""
        eng = self.get_engagement(engagement_id)
        if not eng:
            return {"error": "Engagement not found"}
        return {
            "engagement": eng,
            "generated_at": _now_iso(),
            "scope": self.list_scope(engagement_id),
            "assets": self.list_assets(engagement_id),
            "sections": {s: self.get_section_status(engagement_id, s) for s in ASSESSMENT_SECTIONS},
            "responses": {s: self.list_responses(engagement_id, s) for s in ASSESSMENT_SECTIONS},
            "findings": self.list_findings(engagement_id),
            "evidence": self.list_evidence(engagement_id),
            "risk_register": self.list_risk_register(engagement_id),
            "dlp": {
                "data_records": self.list_dlp_data_records(engagement_id),
                "data_flows": self.list_data_flows(engagement_id),
                "controls": self.list_dlp_controls(engagement_id),
                "validations": self.list_dlp_validations(engagement_id),
            },
            "remediation": self.list_remediation_actions(engagement_id=engagement_id),
            "retests": self.list_retests(engagement_id),
            "reports": self.list_reports(engagement_id),
            "audit_log": self.list_audit_log(engagement_id, limit=500),
        }

    # ------------------------------------------------------------------ #
    # Section Response Initialization
    # ------------------------------------------------------------------ #

    def initialize_section_responses(self, engagement_id: str, section: str | None = None) -> int:
        """
        Ensure all active questions for a section have a NOT_ASSESSED response row.
        Call this when an assessor first opens a section.
        Returns count of newly created rows.
        """
        questions = self.list_questions(section=section)
        created = 0
        for q in questions:
            r = self.get_or_create_response(engagement_id, q["id"])
            if r.get("status") == "NOT_ASSESSED" and not r.get("assessed_by"):
                created += 1
        return created

    def initialize_all_sections(self, engagement_id: str) -> int:
        """Initialize responses for all sections."""
        total = 0
        for section in ASSESSMENT_SECTIONS:
            total += self.initialize_section_responses(engagement_id, section)
        return total


# ---------------------------------------------------------------------------
# Module-level singleton (lazy)
# ---------------------------------------------------------------------------

_store: EngagementStore | None = None


def get_store(db_path: str = "data/llm_audit.db") -> EngagementStore:
    """Return or create the module-level store singleton."""
    global _store
    if _store is None:
        _store = EngagementStore(db_path=db_path)
    return _store
