"""
Port Scan Routes Blueprint - Integrated from CyberScan
Flask routes for port scanning functionality integrated into NiteSentinel.

NiteSentinel v1.2 Enterprise - Unified Port Scanning Routes
"""
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
import logging
import ipaddress
import json
import os
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from nitesentinels.web.app import login_required as app_login_required
        return app_login_required(f)(*args, **kwargs)
    return decorated

from nitesentinels.scanners.port_scanner_async import scan_generator_sync, parse_ports
from nitesentinels.scanners.service_detector import analyze_port_scan

logger = logging.getLogger(__name__)

# Create blueprint
port_scan_bp = Blueprint('port_scan', __name__, url_prefix='/port-scan')

# Private IP ranges that should not be scanned publicly
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is in private ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_IP_RANGES)
    except ValueError:
        # If not IP, assume it's hostname (allow it)
        return False


def require_auth(f):
    """
    Decorator to require authentication for sensitive routes.
    Can be applied to routes that should only work for authenticated users.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In single-user mode, allow; in enterprise, require login_required
        return f(*args, **kwargs)
    return decorated_function


def _private_scan_blocked_response(target: str):
    """Return a friendly error response when a private IP is blocked."""
    return Response(
        f"data: {json.dumps({'type': 'error', 'message': f'Private IP {target} is not allowed for external scans. Use the local scan feature for internal networks.'})}\n\n",
        mimetype="text/event-stream"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public Quick Scan Routes
# ──────────────────────────────────────────────────────────────────────────────

@port_scan_bp.route('/quick-scan')
def quick_scan_page():
    """Quick scan page (public access)."""
    from flask import session
    username = session.get('username', 'guest')
    role = session.get('role', 'viewer')
    return render_template('port_scan.html', demo_mode=False, username=username, role=role)


@port_scan_bp.route('/stream-quick-scan')
def stream_quick_scan():
    """Stream quick scan results in real-time."""
    target = request.args.get('target', '').strip()
    ports = request.args.get('ports', '1-1024').strip()
    
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    # Security: Block private IP ranges for public scans
    try:
        if is_private_ip(target):
            logger.warning(f"Blocked scan attempt on private IP: {target}")
            return jsonify({"error": "Private IP ranges not allowed for quick scan"}), 403
    except Exception as e:
        logger.warning(f"Error checking IP: {e}")
    
    logger.info(f"Quick scan started on {target} (ports: {ports})")
    
    def scan_stream():
        scanned_count = 0
        open_count = 0
        try:
            for port, is_open, service, banner in scan_generator_sync(
                target, ports=ports, concurrency=100, timeout=1.0, service_probe=True
            ):
                scanned_count += 1
                if is_open:
                    open_count += 1
                    data = {
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "status": "open",
                        "scanned": scanned_count,
                        "open": open_count
                    }
                    yield f"data: {__import__('json').dumps(data)}\n\n"
        except Exception as e:
            logger.error(f"Scan error: {e}")
            yield f"data: {__import__('json').dumps({'error': str(e)})}\n\n"
    
    return Response(scan_stream(), mimetype='text/event-stream')


# ──────────────────────────────────────────────────────────────────────────────
# Authenticated Scan Routes
# ──────────────────────────────────────────────────────────────────────────────

@port_scan_bp.route('/authenticated-scan', methods=['GET', 'POST'])
@login_required
def authenticated_scan():
    """Full scan for authenticated users (with history tracking)."""
    if request.method == 'GET':
        from flask import session
        username = session.get('username', 'admin')
        role = session.get('role', 'admin')
        return render_template('port_scan.html', demo_mode=False, username=username, role=role, authenticated=True)
    
    # POST: Start scan
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    ports = data.get('ports', '1-1024').strip()
    
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    logger.info(f"Authenticated scan: {target} (ports: {ports}) by {request.remote_addr}")
    
    def scan_stream():
        try:
            open_ports = []
            for port, is_open, service, banner in scan_generator_sync(
                target, ports=ports, concurrency=100, timeout=1.0, service_probe=True
            ):
                if is_open:
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner
                    })
                    yield f"data: {__import__('json').dumps({'port': port, 'service': service, 'status': 'open'})}\n\n"
            
            # Analyze results
            if open_ports:
                analysis = analyze_port_scan(open_ports)
                yield f"data: {__import__('json').dumps({'analysis': analysis, 'type': 'analysis'})}\n\n"
        except Exception as e:
            logger.error(f"Authenticated scan error: {e}")
            yield f"data: {__import__('json').dumps({'error': str(e)})}\n\n"
    
    return Response(scan_stream(), mimetype='text/event-stream')


@port_scan_bp.route('/scan-history')
@login_required
def scan_history():
    """View scan history for authenticated user."""
    from flask import redirect, url_for
    return redirect(url_for('dashboard'))


@port_scan_bp.route('/api/scan-history', methods=['GET'])
@login_required
def api_scan_history():
    """API endpoint for scan history."""
    # TODO: Implement database storage of scan results
    return jsonify({"scans": []})


# ──────────────────────────────────────────────────────────────────────────────
# Admin Routes
# ──────────────────────────────────────────────────────────────────────────────

@port_scan_bp.route('/admin/settings')
@login_required
def admin_scan_settings():
    """Port scan settings for admins."""
    # TODO: Check admin privileges
    return render_template('port_scan_settings.html')


@port_scan_bp.route('/api/scan-status/<scan_id>')
def api_scan_status(scan_id):
    """Get status of ongoing scan."""
    # TODO: Implement scan tracking with unique IDs
    return jsonify({"status": "completed", "progress": 100})


# ──────────────────────────────────────────────────────────────────────────────
# Utility Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@port_scan_bp.route('/api/port-info')
def api_port_info():
    """Get information about common ports."""
    from nitesentinels.scanners.service_detector import PORT_RISK_MAP, detect_service
    
    ports_str = request.args.get('ports', '') or request.args.get('port', '')
    ports = [p.strip() for p in ports_str.split(',') if p.strip()]
    
    if len(ports) == 1:
        try:
            port = int(ports[0])
            service = detect_service(port, '')
            severity, description = PORT_RISK_MAP.get(port, ('low', 'No known risk details'))
            return jsonify({
                "port": port,
                "service": service,
                "risk": severity,
                "description": description
            })
        except ValueError:
            pass
            
    info = {}
    for port_str in ports:
        try:
            port = int(port_str.strip())
            if port in PORT_RISK_MAP:
                severity, description = PORT_RISK_MAP[port]
                info[port] = {
                    "severity": severity,
                    "description": description,
                    "service": detect_service(port, '')
                }
        except (ValueError, AttributeError):
            pass
    
    return jsonify(info)


@port_scan_bp.route('/api/validate-target', methods=['POST'])
def api_validate_target():
    """Validate target before scanning."""
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({"valid": False, "reason": "No target provided"}), 400
    
    # Check for private IPs in public scans
    if is_private_ip(target):
        return jsonify({
            "valid": False,
            "reason": "Private IP ranges not allowed for public scans"
        }), 403
    
    return jsonify({"valid": True})


# Register error handlers for this blueprint
@port_scan_bp.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad request"}), 400


@port_scan_bp.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden"}), 403


@port_scan_bp.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


# ──────────────────────────────────────────────────────────────────────────────
# Merged Recon Helpers and API Endpoints (Integrated from CyberScan)
# ──────────────────────────────────────────────────────────────────────────────

import ssl
import socket
import datetime
import subprocess
import sys
import json
import re
import requests
from urllib.parse import urlparse

from nitesentinels.scanners.sonic_recon import (
    analyze_ssl,
    analyze_dns,
    analyze_whois,
    analyze_ping,
    analyze_headers,
    analyze_subdomains,
    analyze_geolocation,
    analyze_cve,
)

def _client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def _host_from_url(url: str) -> str:
    if not url:
        return ""
    u = url.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    try:
        p = urlparse(u)
        return (p.hostname or "").strip()
    except ValueError:
        return ""

def _parse_ping_metrics(output: str, reachable: bool):
    loss_pct = None
    avg_ms = None
    if not output:
        return loss_pct, avg_ms
    m = re.search(r"\((\d+)%\s*loss\)", output, re.I)
    if m:
        loss_pct = float(m.group(1))
    if loss_pct is None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s*packet\s*loss", output, re.I)
        if m:
            loss_pct = float(m.group(1))
    m = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.I)
    if m:
        avg_ms = float(m.group(1))
    if avg_ms is None:
        m = re.search(
            r"=\s*[\d.]+\s*/\s*([\d.]+)\s*/\s*[\d.]+\s*/\s*[\d.]+\s*ms",
            output,
            re.I,
        )
        if m:
            avg_ms = float(m.group(1))
    if loss_pct is None and not reachable:
        loss_pct = 100.0
    return loss_pct, avg_ms

def _host_matches_cert(host: str, cn: str, sans: list) -> bool:
    host = (host or "").lower().strip().rstrip(".")
    cn = (cn or "").lower().strip()
    if cn.startswith("*."):
        base = cn[2:]
        if host == base or host.endswith("." + base):
            return True
    if cn and (host == cn or host.endswith("." + cn)):
        return True
    for s in sans or []:
        s = str(s).lower().strip()
        if s.startswith("*."):
            b = s[2:]
            if host == b or host.endswith("." + b):
                return True
        if host == s:
            return True
    return False

def _ssl_cert_extras(cert, host: str, ssock) -> dict:
    extras = {
        "signature_algorithm": "",
        "self_signed": False,
        "subject_mismatch": False,
        "chain_incomplete": False,
    }
    try:
        subj = dict(x[0] for x in cert.get("subject", ()))
        cn = subj.get("commonName", "") or subj.get("commonname", "")
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        extras["self_signed"] = cert.get("subject") == cert.get("issuer")
        extras["subject_mismatch"] = not _host_matches_cert(host, cn, sans)
    except Exception:
        pass
    try:
        der = ssock.getpeercert(binary_form=True)
        if der:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                co = x509.load_der_x509_certificate(der, default_backend())
                extras["signature_algorithm"] = co.signature_algorithm_oid._name
            except Exception:
                pass
    except Exception:
        pass
    return extras

def _dns_sonic_context(domain: str, records: dict) -> dict:
    ctx = {"dmarc_txt": [], "dkim_found": False, "zone_transfer_exposed": False}
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        try:
            ans = dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=4)
            ctx["dmarc_txt"] = [str(r).strip('"') for r in ans]
        except Exception:
            pass
        for sel in ("default", "google", "selector1", "selector2", "k1", "smtp", "mandrill", "s1", "s2"):
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=2)
                ctx["dkim_found"] = True
                break
            except Exception:
                continue
        try:
            ns_ans = dns.resolver.resolve(domain, "NS", lifetime=4)
            for ns in ns_ans:
                ns_host = str(ns.target).rstrip(".")
                try:
                    a_ans = dns.resolver.resolve(ns_host, "A", lifetime=3)
                    ns_ip = str(a_ans[0])
                    xfr = dns.query.xfr(ns_ip, domain, lifetime=3)
                    dns.zone.from_xfr(xfr)
                    ctx["zone_transfer_exposed"] = True
                    break
                except Exception:
                    continue
        except Exception:
            pass
    except ImportError:
        pass
    return ctx

def _whois_sonic_context(w, result: dict) -> dict:
    out = dict(result)
    emails = out.get("emails")
    es = ""
    if emails:
        if isinstance(emails, list):
            es = " ".join(str(e) for e in emails).lower()
        else:
            es = str(emails).lower()
    redacted = "redact" in es or "data protected" in es or "gdpr" in es or not es
    out["privacy_disabled"] = bool(es and "@" in es and not redacted)
    try:
        ud = getattr(w, "updated_date", None)
        if isinstance(ud, list) and ud:
            ud = ud[0]
        if isinstance(ud, datetime.datetime):
            age_days = (datetime.datetime.utcnow() - ud.replace(tzinfo=None)).days
            if 0 <= age_days <= 30:
                out["recent_transfer"] = True
    except Exception:
        pass
    return out

def _next_run_iso(frequency, from_dt=None):
    from datetime import datetime, timedelta
    ref = from_dt or datetime.utcnow()
    f = frequency.strip().lower()
    if f == "hourly":
        return (ref + timedelta(hours=1)).isoformat()
    if f == "weekly":
        return (ref + timedelta(weeks=1)).isoformat()
    return (ref + timedelta(days=1)).isoformat() # default daily


@port_scan_bp.route("/api/ssl_check", methods=["POST"])
@login_required
def ssl_check():
    data = request.json or {}
    host = (
        data.get("host", "")
        .strip()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )
    port = int(data.get("port", 443))
    if not host:
        return jsonify({"error": "host required"}), 400
    if is_private_ip(host):
        return _private_scan_blocked_response(host)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                extras = _ssl_cert_extras(cert, host, ssock)

        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_dt - datetime.datetime.utcnow()).days

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        payload = {
            "host": host,
            "valid": True,
            "subject": subject.get("commonName", host),
            "issuer": issuer.get("organizationName", "Unknown"),
            "expires": expire_str,
            "days_left": days_left,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "Unknown",
            "sans": sans[:10],
            **extras,
        }
        payload["ai_analysis"] = analyze_ssl(payload)
        return jsonify(payload)
    except ssl.SSLCertVerificationError as e:
        bad = {"host": host, "valid": False, "error": f"Certificate invalid: {e}"}
        bad["ai_analysis"] = analyze_ssl(bad)
        return jsonify(bad)
    except Exception as e:
        err = {"host": host, "valid": False, "error": str(e)}
        err["ai_analysis"] = analyze_ssl(err)
        return jsonify(err), 500


@port_scan_bp.route("/api/dns_lookup", methods=["POST"])
@login_required
def dns_lookup():
    data = request.json or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    try:
        import dns.resolver
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        sonic_ctx = _dns_sonic_context(domain, records)
        payload = {"domain": domain, "records": records, **sonic_ctx}
        payload["ai_analysis"] = analyze_dns(payload)
        return jsonify(payload)
    except ImportError:
        try:
            ip = socket.gethostbyname(domain)
            records = {"A": [ip], "note": "Install dnspython for full lookup"}
            payload = {"domain": domain, "records": records}
            payload["ai_analysis"] = analyze_dns(payload)
            return jsonify(payload)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/whois", methods=["POST"])
@login_required
def whois_lookup():
    data = request.json or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    try:
        import whois
        w = whois.whois(domain)

        def safe(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else None

        result = {
            "domain": domain,
            "registrar": safe(w.registrar),
            "creation_date": safe(w.creation_date),
            "expiration_date": safe(w.expiration_date),
            "updated_date": safe(w.updated_date),
            "name_servers": safe(w.name_servers),
            "status": safe(w.status),
            "emails": safe(w.emails),
            "country": safe(w.country),
            "org": safe(w.org),
        }
        result = _whois_sonic_context(w, result)
        result["ai_analysis"] = analyze_whois(result)
        return jsonify(result)
    except ImportError:
        return jsonify(
            {"error": "python-whois not installed. Run: pip install python-whois"}
        ), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/ping", methods=["POST"])
@login_required
def ping():
    data = request.json or {}
    host = data.get("host", "").strip()
    count = min(int(data.get("count", 4)), 10)
    if not host:
        return jsonify({"error": "host required"}), 400
    if is_private_ip(host):
        return _private_scan_blocked_response(host)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")
    if not all(c in allowed for c in host):
        return jsonify({"error": "Invalid host"}), 400
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-w", "2000", host]
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout or result.stderr
        reachable = result.returncode == 0
        rtt = None
        for line in output.splitlines():
            if "rtt" in line or "round-trip" in line or "Average" in line:
                parts = line.split("=")
                if len(parts) > 1:
                    seg = parts[1].strip()
                    if "/" in seg:
                        rtt = seg.split("/")[1].strip() + " ms"
                    else:
                        rtt = seg.split(" ")[0] + " ms"
        loss_pct, avg_ms = _parse_ping_metrics(output, reachable)
        payload = {
            "host": host,
            "reachable": reachable,
            "output": output,
            "avg_rtt": rtt,
            "packet_loss_pct": loss_pct,
            "avg_latency_ms": avg_ms,
        }
        payload["ai_analysis"] = analyze_ping(payload)
        return jsonify(payload)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


_SUBDOMAIN_PREFIXES = (
    "www", "mail", "ftp", "admin", "administrator", "vpn", "remote", "dev", "staging", "test", "beta", "api",
    "dashboard", "portal", "webmail", "cpanel", "backup", "old", "legacy", "internal", "intranet", "jenkins",
    "gitlab", "jira", "cdn", "blog", "shop", "img", "static", "m", "app", "secure", "support", "docs", "status",
)


@port_scan_bp.route("/api/headers_analyze", methods=["POST"])
@login_required
def headers_analyze():
    data = request.json or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    hdr_host = _host_from_url(url)
    if hdr_host and is_private_ip(hdr_host):
        return _private_scan_blocked_response(hdr_host)
    try:
        res = requests.get(url, timeout=7, verify=False, headers={"User-Agent": "NiteSentinel-Recon/1.1"})
        hdrs = dict(res.headers)
        payload = {"url": url, "headers": hdrs, "status_code": res.status_code}
        payload["ai_analysis"] = analyze_headers(payload)
        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/subdomain_scan", methods=["POST"])
@login_required
def subdomain_scan():
    try:
        data = request.json or {}
        raw_domain = (data.get("domain") or "").strip()
        if not raw_domain:
            return jsonify({"error": "Domain is required"}), 400

        # Clean domain input: strip protocol, paths, and ports
        clean_domain = re.sub(r"^https?://", "", raw_domain, flags=re.I)
        domain = clean_domain.split("/")[0].split(":")[0].strip().lower().rstrip(".")
        if not domain:
            return jsonify({"error": "Invalid domain format"}), 400

        import socket
        from concurrent.futures import ThreadPoolExecutor

        def check_sub(prefix: str):
            sub = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(sub)
                return {"subdomain": sub, "name": sub, "ip": ip}
            except (socket.gaierror, socket.herror, OSError):
                return None

        found = []
        with ThreadPoolExecutor(max_workers=25) as executor:
            for r in executor.map(check_sub, _SUBDOMAIN_PREFIXES):
                if r:
                    found.append(r)

        payload = {"domain": domain, "subdomains": found}
        payload["ai_analysis"] = analyze_subdomains(found)
        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/geolocation", methods=["POST"])
@login_required
def geolocation():
    data = request.json or {}
    raw_ip = (data.get("ip") or "").strip()
    if not raw_ip:
        raw_ip = _client_ip()

    ip = re.sub(r"^https?://", "", raw_ip, flags=re.I).split(":")[0].split("/")[0].strip()

    # Resolve hostname if domain was provided
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            import socket
            ip = socket.gethostbyname(ip)
        except Exception:
            return jsonify({"error": f"Could not resolve host: {raw_ip}"}), 400

    # Gracefully handle private RFC1918 / Loopback addresses
    if is_private_ip(ip):
        payload = {
            "ip": ip,
            "country": "Private Network",
            "country_code": "LAN",
            "city": "Internal / RFC 1918 Subnet",
            "region": "Intranet / VPN",
            "isp": "Local Enterprise Infrastructure",
            "org": "Private RFC 1918 Address Space",
            "raw": {
                "status": "success",
                "message": "Private / Internal Network IP (RFC 1918). Internal addresses do not have public geographic coordinates."
            }
        }
        payload["ai_analysis"] = {
            "score": 0,
            "risk_level": "Low",
            "findings": [{"severity": "low", "text": f"Private IP {ip} is non-routable on public internet and confined to local network."}],
            "remediation": []
        }
        return jsonify(payload)

    # Public IP lookup with resilient fallbacks
    geo_data = {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=6
        )
        if r.status_code == 200:
            res = r.json()
            if res.get("status") == "success":
                geo_data = {
                    "ip": ip,
                    "country": res.get("country"),
                    "country_code": res.get("countryCode"),
                    "city": res.get("city"),
                    "region": res.get("regionName"),
                    "isp": res.get("isp"),
                    "org": res.get("org") or res.get("as"),
                    "lat": res.get("lat"),
                    "lon": res.get("lon"),
                    "raw": res
                }
    except Exception as e:
        logger.warning("ip-api lookup error for %s: %s", ip, e)

    if not geo_data:
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
            if r.status_code == 200:
                res = r.json()
                geo_data = {
                    "ip": ip,
                    "country": res.get("country_name"),
                    "country_code": res.get("country_code"),
                    "city": res.get("city"),
                    "region": res.get("region"),
                    "isp": res.get("org"),
                    "org": res.get("org"),
                    "lat": res.get("latitude"),
                    "lon": res.get("longitude"),
                    "raw": res
                }
        except Exception as e:
            logger.warning("ipapi.co fallback error for %s: %s", ip, e)

    if not geo_data:
        return jsonify({"error": f"Unable to retrieve geolocation for {ip} (service unavailable or rate-limited)."}), 502

    geo_data["ai_analysis"] = analyze_geolocation(geo_data)
    return jsonify(geo_data)


@port_scan_bp.route("/api/cve_search", methods=["POST"])
@login_required
def cve_search():
    data = request.json or {}
    query = (data.get("query") or data.get("keyword") or "").strip()
    if not query:
        return jsonify({"error": "query or keyword required"}), 400

    parsed_cves = []
    raw_res = {}
    try:
        import urllib.parse
        encoded_query = urllib.parse.quote(query)
        headers = {"User-Agent": "NiteSentinel-CyberRecon/1.1"}
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}&resultsPerPage=25",
            headers=headers,
            timeout=12
        )
        if r.status_code == 200:
            raw_res = r.json()
            vulns = raw_res.get("vulnerabilities", [])
            for item in vulns:
                c = item.get("cve", {})
                cid = c.get("id", "")
                if not cid:
                    continue
                descs = c.get("descriptions", [])
                desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
                if not desc and descs:
                    desc = descs[0].get("value", "")

                metrics = c.get("metrics", {})
                score = None
                sev = "INFO"
                for mkey in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if mkey in metrics and metrics[mkey]:
                        m = metrics[mkey][0]
                        cvss = m.get("cvssData", {})
                        score = cvss.get("baseScore")
                        sev = cvss.get("baseSeverity") or m.get("baseSeverity") or "UNKNOWN"
                        break

                parsed_cves.append({
                    "id": cid,
                    "description": desc,
                    "severity": str(sev).upper(),
                    "base_score": score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}"
                })
        else:
            logger.warning("NVD API returned %s: %s", r.status_code, r.text[:200])
    except Exception as e:
        logger.warning("NVD API query error: %s", e)

    crit_count = sum(1 for c in parsed_cves if c.get("severity") == "CRITICAL")
    high_count = sum(1 for c in parsed_cves if c.get("severity") == "HIGH")
    max_cvss = max((float(c.get("base_score") or 0.0) for c in parsed_cves), default=0.0)

    payload = {
        "query": query,
        "total": len(parsed_cves),
        "cves": parsed_cves,
        "critical_count": crit_count,
        "high_count": high_count,
        "max_cvss": max_cvss,
        "raw": raw_res
    }
    payload["ai_analysis"] = analyze_cve(payload)
    return jsonify(payload)


@port_scan_bp.route("/api/breach-check", methods=["POST"])
@login_required
def breach_check():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    if not api_key:
        return jsonify({
            "error": "HaveIBeenPwned API key not configured on server.",
            "hint": "Set HIBP_API_KEY environment variable with your HIBP v3 key to enable breach checks."
        }), 503
    try:
        headers = {"hibp-api-key": api_key, "user-agent": "NiteSentinel-Enterprise"}
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}", headers=headers, timeout=6)
        if r.status_code == 200:
            return jsonify({"breached": True, "results": r.json()})
        if r.status_code == 404:
            return jsonify({"breached": False, "results": []})
        return jsonify({"error": f"HIBP returned status {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/schedules", methods=["GET", "POST"])
@login_required
def schedules():
    from nitesentinels.web.app import llm_store
    from flask import session
    try:
        user_id = session.get("user_id") or session.get("username") or "anonymous"
        if request.method == "GET":
            schedules_list = llm_store.list_schedules(user_id)
            return jsonify({"schedules": schedules_list})
        
        data = request.get_json(silent=True) or {}
        target = (data.get("target") or "").strip()
        ports = (data.get("ports") or "1-1024").strip()
        frequency = (data.get("frequency") or "").strip().lower()
        notify = 1 if data.get("notify_email") else 0
        if not target or frequency not in ("daily", "weekly", "monthly"):
            return jsonify({"error": "Invalid schedule"}), 400
        if is_private_ip(target):
            return _private_scan_blocked_response(target)
        logger.info("Scan: schedule_portscan on %s by %s", target, user_id)
        nr = _next_run_iso(frequency)
        llm_store.add_schedule(user_id, target, ports, frequency, nr, notify)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@port_scan_bp.route("/api/schedules/<int:sid>", methods=["DELETE"])
@login_required
def schedule_delete(sid):
    from nitesentinels.web.app import llm_store
    from flask import session
    try:
        user_id = session.get("user_id") or session.get("username") or "anonymous"
        llm_store.delete_schedule(sid, user_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


from flask import stream_with_context

@port_scan_bp.route("/stream_scan")
@login_required
def stream_scan():
    from flask import session
    user_id = session.get("user_id") or session.get("username") or "anonymous"
    target = request.args.get("target")
    ports = request.args.get("ports", "1-1024")
    threads = int(request.args.get("threads", 100))
    timeout = float(request.args.get("timeout", 1.0))
    service = request.args.get("service") == "on"

    if not target:
        return jsonify({"error": "target required"}), 400

    try:
        port_list = parse_ports(ports)
        if len(port_list) > 10000:
            return jsonify(
                {"error": "Port range too large. Maximum 10000 ports allowed."}
            ), 400
    except Exception:
        return jsonify({"error": "Invalid port range"}), 400

    # Allow private IPs — this is an enterprise internal security tool
    logger.info("Scan: stream_portscan on %s by %s", target, user_id)

    def generate():
        try:
            total_ports = len(parse_ports(ports))
        except Exception:
            total_ports = 0
        yield f"data: {json.dumps({'type': 'meta', 'total': total_ports})}\n\n"
        scanned_count = 0
        opens = []
        try:
            for port, is_open, svc, banner in scan_generator_sync(
                target, ports, threads, timeout, service
            ):
                scanned_count += 1
                if is_open:
                    opens.append({"port": port, "service": svc, "banner": banner})
                msg = {
                    "type": "result",
                    "port": port,
                    "open": is_open,
                    "service": svc,
                    "banner": banner,
                    "scanned": scanned_count,
                }
                yield f"data: {json.dumps(msg)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'complete', 'ai_analysis': analyze_port_scan(opens)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@port_scan_bp.route("/check_port", methods=["POST"])
@login_required
def check_port():
    data = request.json or {}
    target = data.get("target")
    port = data.get("port")
    if not target or not port:
        return jsonify({"error": "Target and port required"}), 400
    if is_private_ip(target):
        return jsonify({"error": "Private IP ranges not allowed"}), 403
    
    from flask import session
    user_id = session.get("user_id") or session.get("username") or "anonymous"
    logger.info("Scan: check_port on %s by %s", target, user_id)
    try:
        port = int(port)
        from nitesentinels.scanners.port_scanner_async import scan_generator_sync
        is_open = False
        for p, o, svc, banner in scan_generator_sync(target, ports=str(port), concurrency=1, timeout=2.0, service_probe=False):
            if p == port and o:
                is_open = True
                break
        return jsonify({"target": target, "port": port, "open": is_open})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

