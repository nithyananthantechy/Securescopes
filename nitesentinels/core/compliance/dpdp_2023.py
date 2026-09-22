"""
India's Digital Personal Data Protection (DPDP) Act 2023 Framework definition.
This module defines the clauses and security mapping rules for the DPDP Act 2023.
"""

DPDP_2023_FRAMEWORK = {
    "name": "India DPDP Act 2023",
    "version": "2023",
    "controls": {
        "DPDP-8.5": {
            "title": "Security Safeguards & Personal Data Protection",
            "domain": "Clause 8: Obligations of Data Fiduciary",
            "description": "Every Data Fiduciary shall protect personal data in its possession or under its control by taking reasonable security safeguards to prevent personal data breach."
        },
        "DPDP-8.6": {
            "title": "Data Breach Notification",
            "domain": "Clause 8: Obligations of Data Fiduciary",
            "description": "In the event of a personal data breach, the Data Fiduciary shall give the Board and each affected Data Principal, intimation of such breach."
        },
        "DPDP-9.0": {
            "title": "Significant Data Fiduciary Obligations",
            "domain": "Clause 9: Significant Data Fiduciary",
            "description": "Significant Data Fiduciaries must appoint a DPO, conduct periodic audits, and perform Data Protection Impact Assessments (DPIA)."
        },
        "DPDP-11.0": {
            "title": "Rights of Data Principals",
            "domain": "Clause 11: Rights & Duties of Data Principal",
            "description": "Data Principals have the right to access information, seek correction, completion, updating, or erasure of their personal data."
        }
    }
}

def map_finding_to_dpdp(finding_title: str, finding_details: str) -> list[str]:
    """
    Map scan findings dynamically to appropriate DPDP clauses based on finding content.
    """
    blob = f"{finding_title} {finding_details}".lower()
    clauses = []
    
    # Clause 8.5 mapping: data security safeguards, encryption, password policies, firewall, ports
    if any(x in blob for x in ("password", "encryption", "tls", "ssl", "cve", "patch", "exposed", "port", "firewall", "security")):
        clauses.append("DPDP-8.5")
        
    # Clause 8.6 mapping: audit logs, monitoring, lack of detection of data breach, security alerts
    if any(x in blob for x in ("audit log", "monitoring", "alert", "slack", "email", "logging")):
        clauses.append("DPDP-8.6")
        
    # Clause 9.0 mapping: Significant Data Fiduciary (periodic audits, security scanning cadence, governance)
    if any(x in blob for x in ("audit", "compliance", "policy", "significant")):
        clauses.append("DPDP-9.0")
        
    # Clause 11.0 mapping: erasure, right to access, access controls, public exposed services, data retention
    if any(x in blob for x in ("access control", "user permissions", "erasure", "retention", "anonymization")):
        clauses.append("DPDP-11.0")
        
    # Default safeguard if no specific matches
    if not clauses:
        clauses.append("DPDP-8.5")
        
    return clauses
