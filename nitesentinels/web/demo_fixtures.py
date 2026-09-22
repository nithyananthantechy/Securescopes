from datetime import datetime, timedelta
import uuid

DEMO_ORG = {
    "id": "demo-org-1",
    "name": "Acme Technologies Pvt Ltd",
    "license_id": None,
    "created_at": datetime.utcnow().isoformat()
}

DEMO_TARGETS = {
    "acme-app.example.com": {
        "score": 65,
        "failed": 6,
        "passed": 4,
        "warnings": 5,
        "hostname": "acme-app.example.com",
        "target": "acme-app.example.com",
        "os": "Linux",
        "platform": "Remote",
        "last_scan": (datetime.utcnow() - timedelta(days=1)).strftime("%d %b %Y %H:%M:%S"),
        "org_id": "demo-org-1",
        "checks": [
            # Critical
            {
                "check": "CVE-2024-3400 PAN-OS OS Command Injection",
                "category": "Vulnerability",
                "status": "FAIL",
                "severity": "critical",
                "details": "GlobalProtect feature of Palo Alto Networks PAN-OS software with specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
                "workflow_status": "new",
                "frameworks": ["CIS", "ISO"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "CVE-2023-44487 HTTP/2 Rapid Reset",
                "category": "Vulnerability",
                "status": "FAIL",
                "severity": "critical",
                "details": "The HTTP/2 protocol is susceptible to a denial of service attack (Server Resource Exhaustion) because request cancellation can reset many streams quickly.",
                "workflow_status": "in_progress",
                "frameworks": ["CIS"],
                "assigned_to": "admin",
                "reviewed": True
            },
            # High
            {
                "check": "Exposed SSH port",
                "category": "Network",
                "status": "FAIL",
                "severity": "high",
                "details": "Port 22 is open to the public internet.",
                "workflow_status": "new",
                "frameworks": ["CIS", "NIST", "ISO"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Weak Password Policy",
                "category": "Identity",
                "status": "FAIL",
                "severity": "high",
                "details": "Password policy does not enforce complexity or length requirements.",
                "workflow_status": "new",
                "frameworks": ["ISO", "CIS", "NIST"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Missing Database Encryption at Rest",
                "category": "Data Protection",
                "status": "FAIL",
                "severity": "high",
                "details": "The primary database volume is not encrypted.",
                "workflow_status": "new",
                "frameworks": ["CIS", "PCI", "ISO"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "CVE-2021-44228 Log4j Vulnerability",
                "category": "Vulnerability",
                "status": "FAIL",
                "severity": "high",
                "details": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "workflow_status": "remediated",
                "frameworks": ["CIS"],
                "assigned_to": "admin",
                "reviewed": True
            },
            # Medium
            {
                "check": "Insecure TLS Configuration",
                "category": "Network",
                "status": "WARNING",
                "severity": "medium",
                "details": "Server supports TLS 1.1 which is considered deprecated.",
                "workflow_status": "new",
                "frameworks": ["CIS", "PCI"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Missing Security Headers",
                "category": "Web",
                "status": "WARNING",
                "severity": "medium",
                "details": "HTTP response missing Strict-Transport-Security and Content-Security-Policy.",
                "workflow_status": "new",
                "frameworks": ["OWASP", "CIS"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "SMBv1 Enabled",
                "category": "Network",
                "status": "WARNING",
                "severity": "medium",
                "details": "Server has SMBv1 enabled which is vulnerable to exploits.",
                "workflow_status": "new",
                "frameworks": ["CIS"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Anonymous FTP Access Allowed",
                "category": "Network",
                "status": "WARNING",
                "severity": "medium",
                "details": "Anonymous user can log into the FTP server.",
                "workflow_status": "new",
                "frameworks": ["CIS", "ISO"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Unrestricted Outbound Traffic",
                "category": "Network",
                "status": "WARNING",
                "severity": "medium",
                "details": "Servers can initiate connections to any external IP on any port.",
                "workflow_status": "new",
                "frameworks": ["CIS"],
                "assigned_to": None,
                "reviewed": False
            },
            # Low
            {
                "check": "Information Disclosure - Server Header",
                "category": "Web",
                "status": "PASS", # Treat as low severity finding
                "severity": "low",
                "details": "Server exposes exact version information in HTTP headers.",
                "workflow_status": "new",
                "frameworks": ["OWASP"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Missing DNS CAA Record",
                "category": "Network",
                "status": "PASS",
                "severity": "low",
                "details": "Domain does not have a Certificate Authority Authorization record.",
                "workflow_status": "new",
                "frameworks": ["CIS"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "Directory Listing Enabled",
                "category": "Web",
                "status": "PASS",
                "severity": "low",
                "details": "Web server permits directory listing on some paths.",
                "workflow_status": "new",
                "frameworks": ["OWASP"],
                "assigned_to": None,
                "reviewed": False
            },
            {
                "check": "SSL Certificate Expiry in 30 Days",
                "category": "Web",
                "status": "PASS",
                "severity": "low",
                "details": "The SSL certificate for the domain will expire soon.",
                "workflow_status": "new",
                "frameworks": ["ISO"],
                "assigned_to": None,
                "reviewed": False
            }
        ]
    }
}
