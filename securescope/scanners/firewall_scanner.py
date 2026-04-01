from securescope.core.utils import run_command, logger

class FirewallScanner:
    def __init__(self, platform_info):
        self.plat = platform_info

    def run_all_checks(self):
        results = []
        if self.plat["os"] == "Linux":
            results.extend(self.check_linux_firewall())
        elif self.plat["os"] == "Windows":
            results.extend(self.check_windows_firewall())
        return results

    def check_linux_firewall(self):
        checks = []
        # Check UFW default policy
        res = run_command("ufw status verbose")
        status = "PASS" if "Default: deny (incoming)" in res["stdout"] else "FAIL"
        checks.append({
            "category": "Firewall",
            "check": "Default Deny Inbound",
            "status": status,
            "severity": "Critical",
            "details": f"Policy: {res['stdout'][:50]}..." if res["success"] else "Could not determine policy"
        })

        # Check for ANY to ANY rules (iptables)
        res = run_command("iptables -L")
        any_any = "ACCEPT     all  --  anywhere             anywhere" in res["stdout"]
        status = "FAIL" if any_any else "PASS"
        checks.append({
            "category": "Firewall",
            "check": "Any-to-Any Rules",
            "status": status,
            "severity": "Critical",
            "details": "Dangerous ANY-to-ANY rule detected in iptables" if any_any else "No open ANY-to-ANY rules"
        })
        return checks

    def check_windows_firewall(self):
        checks = []
        # Check all profiles (Domain, Private, Public)
        res = run_command("powershell.exe -Command \"Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction\"")
        status = "PASS" if "Block" in res["stdout"] else "FAIL"
        checks.append({
            "category": "Firewall",
            "check": "Default Inbound Action",
            "status": status,
            "severity": "Critical",
            "details": "Default action is block" if status == "PASS" else "Default action allows inbound"
        })
        return checks
