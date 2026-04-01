import os
import subprocess
from securescope.core.utils import run_command, logger, detect_platform
from securescope.scanners.linux_scanner import LinuxScanner

class WSLScanner(LinuxScanner):
    def __init__(self):
        super().__init__(target_host="local")
        self.plat_info = detect_platform()

    def run_all_checks(self):
        if not self.plat_info["is_wsl"]:
            return []
            
        results = []
        # Run standard Linux checks first
        results.extend(super().run_all_checks())
        
        # WSL Specific checks
        results.extend(self.check_wsl_info())
        results.extend(self.check_host_access())
        results.extend(self.check_windows_firewall_from_wsl())
        
        return results

    def check_wsl_info(self):
        checks = []
        # Detect WSL version
        res = run_command("uname -r")
        version = "2" if "microsoft-standard-WSL2" in res["stdout"] else "1"
        checks.append({
            "category": "WSL",
            "check": "WSL Version",
            "status": "PASS",
            "severity": "Low",
            "details": f"Running WSL version {version}"
        })
        return checks

    def check_host_access(self):
        checks = []
        # Check if /mnt/c is mounted
        status = "WARNING" if os.path.exists("/mnt/c") else "PASS"
        checks.append({
            "category": "WSL",
            "check": "Host File Access",
            "status": status,
            "severity": "Medium",
            "details": "WSL has access to Windows files via /mnt/c" if status == "WARNING" else "No direct host file access"
        })
        return checks

    def check_windows_firewall_from_wsl(self):
        checks = []
        # Call powershell.exe from WSL
        res = run_command("powershell.exe -Command 'Get-NetFirewallProfile | Select-Object Name, Enabled' 2>/dev/null")
        status = "PASS" if "True" in res["stdout"] or "1" in res["stdout"] else "FAIL"
        if not res["success"]:
            status = "WARNING"
            details = "Could not check host firewall from WSL"
        else:
            details = "Host Windows Firewall is active" if status == "PASS" else "Host Windows Firewall might be disabled"
            
        checks.append({
            "category": "WSL",
            "check": "Host Firewall Status",
            "status": status,
            "severity": "High",
            "details": details
        })
        return checks
