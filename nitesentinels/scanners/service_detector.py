"""
Service Detection Module - Extracted from CyberScan's sonic_recon.py
Provides intelligent service identification and risk scoring for network reconnaissance.

NiteSentinel v1.2 Enterprise - Integrated Port Scanner
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Risk Scoring & Classification
# ──────────────────────────────────────────────────────────────────────────────

def _cap(score: int) -> int:
    """Clamp score between 0-100."""
    return min(max(int(score), 0), 100)


def risk_level_from_score(score: Optional[int]) -> str:
    """Convert numeric score to risk level."""
    if score is None:
        return "Info"
    if score <= 30:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 85:
        return "High"
    return "Critical"


def _result(
    score: Optional[int],
    breakdown: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    remediation: List[Dict[str, Any]],
    *,
    informational: bool = False,
) -> Dict[str, Any]:
    """Format analysis result."""
    rl = risk_level_from_score(0 if score is None and informational else score)
    if informational and score is None:
        rl = "Info"
    return {
        "score": score,
        "risk_level": rl,
        "breakdown": breakdown,
        "findings": findings,
        "remediation": remediation,
        "informational": informational,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Port Risk Analysis
# ──────────────────────────────────────────────────────────────────────────────

PORT_RISK_MAP: Dict[int, Tuple[str, str]] = {
    21: ("high", "FTP allows unencrypted file transfer"),
    22: ("medium", "SSH exposed, brute force risk"),
    23: ("high", "Telnet is unencrypted, replace with SSH"),
    25: ("high", "Mail server exposed publicly"),
    53: ("medium", "DNS exposed, potential amplification risk"),
    80: ("medium", "Unencrypted HTTP in use"),
    110: ("medium", "Legacy mail protocol exposed"),
    139: ("high", "NetBIOS exposed, SMB attack surface"),
    143: ("medium", "Mail retrieval port exposed"),
    443: ("low", "HTTPS present — good"),
    445: ("critical", "SMB exposed — EternalBlue/ransomware risk"),
    1433: ("critical", "Database port publicly exposed"),
    3306: ("critical", "MySQL exposed — critical risk"),
    3389: ("critical", "RDP exposed — ransomware entry point"),
    5432: ("critical", "PostgreSQL exposed publicly"),
    6379: ("critical", "Redis exposed — no auth by default"),
    8080: ("medium", "Alternative HTTP port exposed"),
    27017: ("critical", "MongoDB exposed — data breach risk"),
}


def _open_ports_count_score(n: int) -> Tuple[int, str]:
    """Score based on number of open ports."""
    if n <= 0:
        return 0, "No open ports detected"
    if n <= 3:
        return 15, "1–3 open ports"
    if n <= 9:
        return 30, "4–9 open ports"
    return 50, "10+ open ports"


def analyze_port_scan(open_ports: List[Any]) -> Dict[str, Any]:
    """
    Analyze port scan results and generate risk assessment.
    
    Args:
        open_ports: List of dicts with port, service, banner or list of port numbers
        
    Returns:
        Dict with score, risk_level, breakdown, findings, remediation
    """
    ports: List[int] = []
    meta: Dict[int, Dict[str, str]] = {}
    
    for item in open_ports or []:
        if isinstance(item, dict):
            p = int(item.get("port", 0))
            if p:
                ports.append(p)
                meta[p] = {
                    "service": str(item.get("service") or "unknown"),
                    "banner": str(item.get("banner") or ""),
                }
        elif isinstance(item, int):
            ports.append(item)
    
    ports_sorted = sorted(set(ports))
    n = len(ports_sorted)
    total = 0
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []

    pts, blabel = _open_ports_count_score(n)
    if pts:
        total += pts
        breakdown.append({"factor": "Open port exposure", "impact": pts, "detail": blabel})

    for p in ports_sorted:
        if p in PORT_RISK_MAP:
            sev, msg = PORT_RISK_MAP[p]
            if p == 443:
                findings.append({"severity": "low", "text": f"Port {p} (HTTPS): {msg}", "impact": 0})
                breakdown.append({"factor": f"Port {p} HTTPS", "impact": 0, "detail": msg})
                continue
            # Increase impact per high-risk port to weight critical services more heavily
            add = 15
            total += add
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            findings.append(
                {
                    "severity": sev_map.get(sev, "medium"),
                    "text": f"Port {p}: {msg}",
                    "impact": add,
                }
            )
            breakdown.append({"factor": f"High-risk service port {p}", "impact": add, "detail": msg})
        else:
            findings.append(
                {
                    "severity": "info",
                    "text": f"Port {p} open — review service exposure and firewall rules",
                    "impact": 0,
                }
            )

    total = _cap(total)

    if n == 0:
        findings.insert(0, {"severity": "low", "text": "No open ports found in scanned range.", "impact": 0})
        remediation.append(
            {
                "step": 1,
                "action": "Maintain default-deny ingress; scan regularly after network changes.",
                "code": "",
            }
        )
    else:
        remediation.append(
            {
                "step": 1,
                "action": "Close unused services; restrict management ports (SSH, RDP) to VPN or allow-lists.",
                "code": "# iptables / cloud SG: allow 22/3389 only from trusted CIDRs",
            }
        )
        if any(p in (445, 3389, 3306, 1433, 27017, 6379) for p in ports_sorted):
            remediation.append(
                {
                    "step": 2,
                    "action": "Never expose databases or SMB/RDP directly to the internet; place behind VPN or bastion.",
                    "code": "",
                }
            )

    return _result(total, breakdown, findings, remediation)


# ──────────────────────────────────────────────────────────────────────────────
# Service Detection
# ──────────────────────────────────────────────────────────────────────────────

COMMON_PORT_SERVICES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware-auth",
    912: "vmware-auth",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1434: "mssql-m",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "node-http",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5060: "sip",
    5061: "sips",
    5432: "postgresql",
    5900: "vnc",
    5901: "vnc-1",
    6379: "redis",
    6443: "k8s-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8082: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "prometheus",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elastic-cluster",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
}


def detect_service(port: int, banner: str) -> str:
    """
    Detect service from port number and banner fingerprint.
    
    Args:
        port: Port number
        banner: Banner string from service
        
    Returns:
        Service name string
    """
    b = (banner or '').lower().strip()
    
    # 1. High-fidelity Banner Inspection
    if 'vmware' in b:
        return 'vmware-auth'
    if 'ssh-' in b or 'openssh' in b:
        return 'ssh'
    if b.startswith('http/') or 'server:' in b or '<html' in b or 'apache' in b or 'nginx' in b or 'iis' in b or 'caddy' in b or 'cloudflare' in b:
        return 'https' if port in (443, 8443, 9443, 4443) else 'http'
    if 'smtp' in b or 'postfix' in b or 'exim' in b or 'sendmail' in b or 'esmtp' in b:
        return 'smtp'
    if 'ftp' in b or 'pure-ftpd' in b or 'vsftpd' in b or 'proftpd' in b or 'filezilla' in b:
        return 'ftp'
    if 'mysql' in b or 'mariadb' in b:
        return 'mysql'
    if 'postgresql' in b:
        return 'postgresql'
    if 'redis' in b:
        return 'redis'
    if 'mongodb' in b:
        return 'mongodb'
    if 'msrpc' in b or 'endpoint mapper' in b:
        return 'msrpc'
    if 'smb' in b or 'samba' in b or 'microsoft-ds' in b:
        return 'microsoft-ds'
    if 'netbios' in b:
        return 'netbios-ssn'
    if 'rdp' in b or 'remote desktop' in b:
        return 'rdp'
    if 'vnc' in b or 'rfb ' in b:
        return 'vnc'
    if b.startswith('tls') or b.startswith('ssl'):
        return 'https'

    # 2. Well-Known Port Lookup
    if port in COMMON_PORT_SERVICES:
        return COMMON_PORT_SERVICES[port]

    # 3. System IANA Services Fallback
    try:
        import socket
        svc_name = socket.getservbyport(port, "tcp")
        if svc_name:
            return svc_name
    except (OSError, socket.error):
        pass

    return 'unknown'


# ──────────────────────────────────────────────────────────────────────────────
# SSL/TLS Analysis
# ──────────────────────────────────────────────────────────────────────────────

def analyze_ssl(ssl_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze SSL/TLS certificate and configuration.
    
    Args:
        ssl_data: Dict with certificate info (valid, days_left, signature_algorithm, etc.)
        
    Returns:
        Dict with score, risk_level, findings, remediation
    """
    breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    remediation: List[Dict[str, Any]] = []
    total = 0

    if ssl_data.get("error") or not ssl_data.get("valid", True):
        err = ssl_data.get("error") or "Certificate could not be validated"
        total = _cap(total + 70)
        breakdown.append({"factor": "Certificate / handshake failure", "impact": 70, "detail": err})
        findings.append({"severity": "critical", "text": err, "impact": 70})
        remediation.append(
            {
                "step": 1,
                "action": "Install a valid certificate from a public CA; fix hostname and chain issues.",
                "code": "",
            }
        )
        return _result(_cap(total), breakdown, findings, remediation)

    days_left = int(ssl_data.get("days_left") or 0)
    if days_left < 0:
        total += 60
        breakdown.append({"factor": "Certificate expired", "impact": 60, "detail": "Renew immediately"})
        findings.append({"severity": "critical", "text": "Certificate is expired", "impact": 60})
    elif days_left < 7:
        total += 50
        breakdown.append({"factor": "Expiry < 7 days", "impact": 50, "detail": f"{days_left} days left"})
        findings.append({"severity": "critical", "text": f"Certificate expires in {days_left} days", "impact": 50})
    elif days_left < 30:
        total += 30
        breakdown.append({"factor": "Expiry < 30 days", "impact": 30, "detail": f"{days_left} days left"})
        findings.append({"severity": "high", "text": f"Certificate expires in {days_left} days", "impact": 30})
    elif days_left < 90:
        total += 15
        breakdown.append({"factor": "Expiry < 90 days", "impact": 15, "detail": f"{days_left} days left"})
        findings.append({"severity": "medium", "text": f"Renew within {days_left} days", "impact": 15})
    else:
        breakdown.append({"factor": "Certificate validity window", "impact": 0, "detail": f"{days_left} days remaining — OK"})
        findings.append({"severity": "low", "text": f"Certificate valid ({days_left} days)", "impact": 0})

    sig = (ssl_data.get("signature_algorithm") or "").upper()
    if "MD5" in sig:
        total += 40
        breakdown.append({"factor": "Signature MD5", "impact": 40, "detail": "MD5 is broken"})
        findings.append({"severity": "critical", "text": "MD5 is broken, replace immediately", "impact": 40})
    elif "SHA1" in sig or "SHA-1" in sig:
        total += 25
        breakdown.append({"factor": "Signature SHA1", "impact": 25, "detail": "SHA1 deprecated"})
        findings.append({"severity": "high", "text": "SHA1 is deprecated, upgrade to SHA256", "impact": 25})
    elif sig:
        breakdown.append({"factor": "Signature algorithm", "impact": 0, "detail": sig})
        findings.append({"severity": "low", "text": f"Signature: {sig} — acceptable if SHA256+", "impact": 0})

    if ssl_data.get("self_signed"):
        total += 35
        breakdown.append({"factor": "Self-signed certificate", "impact": 35, "detail": "No public CA trust"})
        findings.append(
            {
                "severity": "high",
                "text": "Self-signed cert causes browser warnings and no CA verification",
                "impact": 35,
            }
        )

    if ssl_data.get("chain_incomplete"):
        total += 20
        breakdown.append({"factor": "Incomplete chain", "impact": 20, "detail": "Intermediate missing"})
        findings.append({"severity": "medium", "text": "Intermediate certificate missing from chain", "impact": 20})

    if ssl_data.get("subject_mismatch"):
        total += 45
        breakdown.append({"factor": "Hostname mismatch", "impact": 45, "detail": "CN/SAN does not match host"})
        findings.append({"severity": "critical", "text": "Certificate does not match the domain", "impact": 45})

    proto = (ssl_data.get("protocol") or "").upper().replace(" ", "")
    tls_add = 0
    tls_msg = ""
    if "SSLV2" in proto or proto == "SSLV2":
        tls_add, tls_msg = 50, "SSLv2 is broken, disable immediately"
    elif "SSLV3" in proto or proto == "SSLV3":
        tls_add, tls_msg = 45, "SSLv3 vulnerable to POODLE"
    elif "TLSV1" == proto or proto.startswith("TLSV1.0"):
        tls_add, tls_msg = 25, "TLS 1.0 deprecated"
    elif "TLSV1.1" in proto or proto.startswith("TLSV1.1"):
        tls_add, tls_msg = 15, "TLS 1.1 deprecated"
    elif "TLSV1.2" in proto or "TLS1.2" in proto:
        tls_add, tls_msg = 5, "TLS 1.2 acceptable; 1.3 preferred"
    elif "TLSV1.3" in proto or "TLS1.3" in proto:
        tls_add, tls_msg = 0, "TLS 1.3 — excellent"
    
    if proto:
        total += tls_add
        breakdown.append({"factor": f"TLS version ({ssl_data.get('protocol')})", "impact": tls_add, "detail": tls_msg or proto})
        findings.append(
            {
                "severity": "critical" if tls_add >= 45 else "high" if tls_add >= 25 else "medium" if tls_add else "low",
                "text": tls_msg or f"Protocol {ssl_data.get('protocol')}",
                "impact": tls_add,
            }
        )

    total = _cap(total)
    if total == 0 or (total <= 15 and days_left >= 90 and not ssl_data.get("subject_mismatch")):
        findings.insert(0, {"severity": "low", "text": "SSL Healthy — no major issues detected", "impact": 0})

    step_n = 1
    if days_left < 30:
        remediation.append({"step": step_n, "action": "Renew certificate before expiry; automate ACME where possible.", "code": ""})
        step_n += 1
    if ssl_data.get("self_signed"):
        remediation.append(
            {
                "step": step_n,
                "action": "Replace with a publicly trusted certificate (Let's Encrypt, commercial CA).",
                "code": "certbot certonly --nginx -d example.com",
            }
        )
        step_n += 1
    if tls_add and tls_add >= 15:
        remediation.append(
            {
                "step": step_n,
                "action": "Disable legacy SSL/TLS; enable TLS 1.2+ and prefer TLS 1.3.",
                "code": "ssl_protocols TLSv1.2 TLSv1.3;",
            }
        )

    return _result(total, breakdown, findings, remediation)
