import os
from securescope.core.utils import run_command, logger

class WebScanner:
    def __init__(self, platform_info):
        self.plat = platform_info

    def run_all_checks(self):
        results = []
        if self.plat["os"] == "Linux":
            results.extend(self.check_nginx())
            results.extend(self.check_apache())
        return results

    def check_nginx(self):
        checks = []
        nginx_conf = "/etc/nginx/nginx.conf"
        if not os.path.exists(nginx_conf):
            return []

        # Server tokens off (Hide version)
        res = run_command(f"grep 'server_tokens' {nginx_conf}")
        status = "PASS" if "off" in res["stdout"] else "FAIL"
        checks.append({
            "category": "Web Server (Nginx)",
            "check": "Hide Version",
            "status": status,
            "severity": "Medium",
            "details": "server_tokens is off" if status == "PASS" else "server_tokens is on or missing"
        })
        return checks

    def check_apache(self):
        checks = []
        apache_conf = "/etc/apache2/apache2.conf"
        if not os.path.exists(apache_conf):
            return []

        # ServerTokens Prod
        res = run_command(f"grep 'ServerTokens' {apache_conf}")
        status = "PASS" if "Prod" in res["stdout"] else "FAIL"
        checks.append({
            "category": "Web Server (Apache)",
            "check": "Hide Version",
            "status": status,
            "severity": "Medium",
            "details": "ServerTokens is Prod" if status == "PASS" else "ServerTokens is not set to Prod"
        })
        return checks
