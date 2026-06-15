from securescope.core.utils import detect_platform, logger
from securescope.scanners.linux_scanner import LinuxScanner
from securescope.scanners.windows_scanner import WindowsScanner
from securescope.scanners.wsl_scanner import WSLScanner
from securescope.scanners.network_scanner import NetworkScanner
from securescope.scanners.firewall_scanner import FirewallScanner
from securescope.scanners.web_scanner import WebScanner
from securescope.scanners.port_scanner import PortScanner
from securescope.scanners.docker_scanner import DockerScanner
import socket
from concurrent.futures import ThreadPoolExecutor

class Scanner:
    def __init__(self):
        self.plat_info = detect_platform()

    def calculate_stats(self, checks):
        """Pure stat calculation from a list of checks."""
        if not checks:
            return {"score": 0, "passed": 0, "failed": 0, "warnings": 0}
        
        passed = sum(1 for c in checks if c.get('status') == 'PASS')
        failed = sum(1 for c in checks if c.get('status') == 'FAIL')
        warnings = sum(1 for c in checks if c.get('status') == 'WARNING')
        score = int((passed / len(checks)) * 100)
        
        return {
            "score": score,
            "passed": passed,
            "failed": failed,
            "warnings": warnings
        }

    def scan_local(self):
        """Perform a clean local scan isolated by platform."""
        logger.info(f"Starting local scan on {self.plat_info['os']}...")
        checks = []
        
        if self.plat_info["is_wsl"]:
            checks.extend(WSLScanner().run_all_checks())
        elif "Linux" in self.plat_info["os"]:
            # Parallel check execution makes local scan faster.
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = [
                    ex.submit(LinuxScanner().run_all_checks),
                    ex.submit(FirewallScanner(self.plat_info).run_all_checks),
                    ex.submit(WebScanner(self.plat_info).run_all_checks),
                    ex.submit(PortScanner("127.0.0.1").run_all_checks),
                    ex.submit(DockerScanner().run_all_checks),
                ]
                for f in futures:
                    checks.extend(f.result())
        elif "Windows" in self.plat_info["os"]:
            checks.extend(WindowsScanner().run_all_checks())
        
        stats = self.calculate_stats(checks)
        return {
            "checks": checks,
            "score": stats["score"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "warnings": stats["warnings"],
            "platform": self.plat_info["os"]
        }

    def scan_remote(self, host, user, password=None, key_path=None, target_type="linux", port=22):
        """Perform a clean remote scan isolated by target type."""
        import socket
        local_ips = ["127.0.0.1", "localhost", "::1"]
        try:
            hostname = socket.gethostname()
            _, _, ips = socket.gethostbyname_ex(hostname)
            local_ips.extend(ips)
        except Exception:
            pass
        if host in local_ips:
            return self.scan_local()
            
        logger.info(f"Starting remote {target_type} scan on {host}:{port}...")
        checks = []
        
        try:
            if target_type == "linux":
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    host,
                    port=int(port),
                    username=user,
                    password=password,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                )
                checks.extend(LinuxScanner(target_host=host, ssh_client=ssh).run_all_checks())
                ssh.close()
            elif target_type == "docker":
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    host,
                    port=int(port),
                    username=user,
                    password=password,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                )
                from securescope.scanners.docker_scanner import DockerScanner
                checks.extend(DockerScanner().scan_remote(ssh))
                ssh.close()
            elif target_type == "network":
                checks.extend(NetworkScanner(host, user, password).run_all_checks())
            elif target_type == "windows":
                import winrm
                session = winrm.Session(
                    f'http://{host}:{port}/wsman',
                    auth=(user, password),
                    transport='ntlm',
                    server_cert_validation='ignore'
                )
                checks.extend(WindowsScanner(target_host=host, winrm_client=session).run_all_checks())
        except Exception as e:
            logger.error(f"Remote scan failed: {str(e)}")
            checks.append({
                "category": "Remote", "check": "Connection",
                "status": "FAIL", "severity": "Critical", "details": str(e)
            })

        stats = self.calculate_stats(checks)
        return {
            "checks": checks,
            "score": stats["score"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "warnings": stats["warnings"],
            "target": host,
            "os": target_type.title()
        }

    def scan_ports(self, host, ports=None):
        """Run a port scan on a target host."""
        logger.info(f"Starting port scan on {host}...")
        port_scanner = PortScanner(host, ports=ports)
        checks = port_scanner.run_all_checks()
        stats = self.calculate_stats(checks)
        return {
            "checks": checks,
            "score": stats["score"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "warnings": stats["warnings"],
            "target": host,
            "os": "Port Scan"
        }

    def scan_web(self, url):
        """Run a web security scan on a URL."""
        import urllib.request
        import ssl
        logger.info(f"Starting web security scan on {url}...")
        checks = []

        # Normalize URL
        if not url.startswith("http"):
            url = "https://" + url

        # 1. SSL/TLS Check
        try:
            if url.startswith("https://"):
                hostname = url.replace("https://", "").split("/")[0].split(":")[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # Check expiry
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.utcnow()).days
                        if days_left < 0:
                            checks.append({"category": "Web Security", "check": "SSL Certificate", "status": "FAIL", "severity": "Critical", "details": f"Certificate EXPIRED {abs(days_left)} days ago"})
                        elif days_left < 30:
                            checks.append({"category": "Web Security", "check": "SSL Certificate", "status": "WARNING", "severity": "High", "details": f"Certificate expires in {days_left} days"})
                        else:
                            checks.append({"category": "Web Security", "check": "SSL Certificate", "status": "PASS", "severity": "Low", "details": f"Valid for {days_left} more days"})
            else:
                checks.append({"category": "Web Security", "check": "HTTPS Enabled", "status": "FAIL", "severity": "Critical", "details": "Site uses HTTP — not encrypted"})
        except Exception as e:
            checks.append({"category": "Web Security", "check": "SSL Certificate", "status": "FAIL", "severity": "Critical", "details": f"SSL check failed: {str(e)}"})

        # 2. Security Headers Check
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NiteSentinel/1.2.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            headers = dict(resp.headers)

            security_headers = {
                "X-Frame-Options": ("Clickjacking Protection", "High"),
                "X-Content-Type-Options": ("MIME Sniffing Protection", "Medium"),
                "Strict-Transport-Security": ("HSTS Enabled", "High"),
                "Content-Security-Policy": ("CSP Configured", "High"),
                "X-XSS-Protection": ("XSS Protection Header", "Medium"),
                "Referrer-Policy": ("Referrer Policy", "Low"),
            }

            for header, (check_name, severity) in security_headers.items():
                if header in headers or header.lower() in [h.lower() for h in headers]:
                    checks.append({"category": "Web Security", "check": check_name, "status": "PASS", "severity": severity, "details": f"{header} is set"})
                else:
                    checks.append({"category": "Web Security", "check": check_name, "status": "FAIL", "severity": severity, "details": f"Missing {header} header"})

            # 3. Server Header Disclosure
            server = headers.get("Server", "")
            if server:
                checks.append({"category": "Web Security", "check": "Server Banner Hidden", "status": "WARNING", "severity": "Medium", "details": f"Server header exposes: {server}"})
            else:
                checks.append({"category": "Web Security", "check": "Server Banner Hidden", "status": "PASS", "severity": "Medium", "details": "Server header not disclosed"})

            # 4. API Security Checks (OWASP)
            api_endpoints = ["/api/docs", "/swagger-ui.html", "/openapi.json", "/v1/api-docs"]
            api_exposed = False
            for endpoint in api_endpoints:
                try:
                    test_url = url.rstrip("/") + endpoint
                    req_api = urllib.request.Request(test_url, headers={"User-Agent": "NiteSentinel/1.2.0"})
                    resp_api = urllib.request.urlopen(req_api, timeout=3)
                    if resp_api.status == 200:
                        checks.append({
                            "category": "API Security", "check": "Exposed API Documentation",
                            "status": "WARNING", "severity": "Medium",
                            "details": f"API Documentation publicly accessible at {endpoint}"
                        })
                        api_exposed = True
                except Exception:
                    pass
            
            if not api_exposed:
                checks.append({
                    "category": "API Security", "check": "Exposed API Documentation",
                    "status": "PASS", "severity": "Low",
                    "details": "No common API documentation endpoints found exposed"
                })

        except Exception as e:
            checks.append({"category": "Web Security", "check": "HTTP Response", "status": "FAIL", "severity": "Critical", "details": f"Could not reach {url}: {str(e)}"})

        stats = self.calculate_stats(checks)
        return {
            "checks": checks,
            "score": stats["score"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "warnings": stats["warnings"],
            "target": url,
            "os": "Web Scan"
        }
