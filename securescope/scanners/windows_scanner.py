import json
from securescope.core.utils import run_command, logger

class WindowsScanner:
    def __init__(self, target_host="local", winrm_client=None):
        self.target_host = target_host
        self.winrm_client = winrm_client

    def execute_ps(self, cmd):
        """Execute PowerShell command safely."""
        if self.target_host == "local":
            full_cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{cmd}\""
            return run_command(full_cmd, timeout=30)
        return {"stdout": "", "stderr": "Remote not implemented", "success": False}

    def run_all_checks(self):
        """Main check runner for Windows. Returns exactly 10 checks."""
        checks = []
        try:
            checks.extend(self.check_user_security())
            checks.extend(self.check_network_security())
            checks.extend(self.check_system_hardening())
            checks.extend(self.check_services())
            checks.extend(self.check_logging())
        except Exception as e:
            logger.error(f"Error during Windows scan: {str(e)}")
        return checks

    def check_user_security(self):
        results = []
        # 1. Guest account disabled
        res = self.execute_ps("Get-LocalUser -Name Guest | Select-Object -ExpandProperty Enabled")
        results.append({
            "category": "User Security",
            "check": "Guest account disabled",
            "status": "PASS" if "False" in res["stdout"] else "FAIL",
            "severity": "Critical",
            "details": "Guest account is disabled" if "False" in res["stdout"] else "Guest account is enabled"
        })
        # 2. Default Admin disabled
        res = self.execute_ps("Get-LocalUser -Name Administrator | Select-Object -ExpandProperty Enabled")
        results.append({
            "category": "User Security",
            "check": "Default Admin disabled",
            "status": "FAIL" if "True" in res["stdout"] else "PASS",
            "severity": "High",
            "details": "Default Administrator account is enabled" if "True" in res["stdout"] else "Default Admin is disabled"
        })
        return results

    def check_network_security(self):
        results = []
        # 3. Windows Firewall Status
        res = self.execute_ps("Get-NetFirewallProfile | Select-Object Enabled")
        status = "PASS" if "1" in res["stdout"] and "0" not in res["stdout"] else "FAIL"
        results.append({
            "category": "Network Security",
            "check": "Windows Firewall Status",
            "status": status,
            "severity": "Critical",
            "details": "All firewall profiles active" if status == "PASS" else "One or more profiles disabled"
        })
        # 4. SMBv1 Disabled
        res = self.execute_ps("Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol")
        results.append({
            "category": "Network Security",
            "check": "SMBv1 Disabled",
            "status": "PASS" if "False" in res["stdout"] else "FAIL",
            "severity": "Critical",
            "details": "SMBv1 is disabled" if "False" in res["stdout"] else "SMBv1 is enabled (Vulnerable)"
        })
        return results

    def check_system_hardening(self):
        results = []
        # 5. Windows Defender Active
        res = self.execute_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled")
        results.append({
            "category": "System Hardening",
            "check": "Windows Defender Active",
            "status": "PASS" if "True" in res["stdout"] else "FAIL",
            "severity": "High",
            "details": "Antivirus is enabled" if "True" in res["stdout"] else "Antivirus is disabled"
        })
        # 6. UAC Enabled
        res = self.execute_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin")
        uac_val = res["stdout"].strip()
        results.append({
            "category": "System Hardening",
            "check": "UAC Enabled",
            "status": "PASS" if uac_val in ["2", "5"] else "FAIL",
            "severity": "High",
            "details": f"UAC Level: {uac_val}"
        })
        return results

    def check_services(self):
        results = []
        # 7. Service Telnet
        res = self.execute_ps("Get-Service -Name TlntSvr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
        results.append({
            "category": "Services",
            "check": "Service Telnet",
            "status": "FAIL" if "Running" in res["stdout"] else "PASS",
            "severity": "Medium",
            "details": "Telnet is running" if "Running" in res["stdout"] else "Telnet is not running"
        })
        # 8. Service FTP
        res = self.execute_ps("Get-Service -Name FTPSVC -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
        results.append({
            "category": "Services",
            "check": "Service FTP",
            "status": "FAIL" if "Running" in res["stdout"] else "PASS",
            "severity": "Medium",
            "details": "FTP is running" if "Running" in res["stdout"] else "FTP is not running"
        })
        # 9. Service Print Spooler
        res = self.execute_ps("Get-Service -Name Spooler | Select-Object -ExpandProperty Status")
        results.append({
            "category": "Services",
            "check": "Service Print Spooler",
            "status": "WARNING" if "Running" in res["stdout"] else "PASS",
            "severity": "Medium",
            "details": f"Spooler is {res['stdout']}"
        })
        return results

    def check_logging(self):
        results = []
        # 10. Event Log Running
        res = self.execute_ps("Get-Service -Name EventLog | Select-Object -ExpandProperty Status")
        results.append({
            "category": "Logging",
            "check": "Event Log Running",
            "status": "PASS" if "Running" in res["stdout"] else "FAIL",
            "severity": "Medium",
            "details": "Event Log is active" if "Running" in res["stdout"] else "Event Log is stopped"
        })
        return results
