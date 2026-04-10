import json
from securescope.core.utils import run_command, logger

class WindowsScanner:
    def __init__(self, target_host="local", winrm_client=None):
        self.target_host = target_host
        self.winrm_client = winrm_client

    def execute_ps(self, cmd):
        """Execute PowerShell command safely."""
        if self.target_host == "local":
            full_cmd = f"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{cmd}\""
            return run_command(full_cmd, timeout=8)
        return {"stdout": "", "stderr": "Remote not implemented", "success": False}

    def execute_cmd(self, cmd, timeout=12):
        """Execute native Windows shell command (faster than PowerShell startup)."""
        if self.target_host == "local":
            return run_command(f'cmd /c "{cmd}"', timeout=timeout)
        return {"stdout": "", "stderr": "Remote not implemented", "success": False}

    def run_all_checks(self):
        """Main check runner for Windows. Returns exactly 10 checks."""
        checks = []
        try:
            # Keep Windows checks sequential to avoid command contention/timeouts on some hosts.
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
        res = self.execute_cmd("net user Guest")
        text = (res.get("stdout") or "").lower()
        guest_enabled = ("account active" in text and "yes" in text) or ("enabled" in text and "true" in text)
        results.append({
            "category": "User Security",
            "check": "Guest account disabled",
            "status": "FAIL" if guest_enabled else "PASS",
            "severity": "Critical",
            "details": "Guest account is enabled" if guest_enabled else "Guest account is disabled"
        })
        # 2. Default Admin disabled
        res = self.execute_cmd("net user Administrator")
        text = (res.get("stdout") or "").lower()
        admin_enabled = ("account active" in text and "yes" in text) or ("enabled" in text and "true" in text)
        results.append({
            "category": "User Security",
            "check": "Default Admin disabled",
            "status": "FAIL" if admin_enabled else "PASS",
            "severity": "High",
            "details": "Default Administrator account is enabled" if admin_enabled else "Default Admin is disabled"
        })
        return results

    def check_network_security(self):
        results = []
        # 3. Windows Firewall Status
        res = self.execute_cmd("netsh advfirewall show allprofiles state")
        text = (res.get("stdout") or "").lower()
        status = "PASS" if "state on" in text and "state off" not in text else "FAIL"
        results.append({
            "category": "Network Security",
            "check": "Windows Firewall Status",
            "status": status,
            "severity": "Critical",
            "details": "All firewall profiles active" if status == "PASS" else "One or more profiles disabled"
        })
        # 4. SMBv1 Disabled
        res = self.execute_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1")
        smb_text = (res.get("stdout") or "").lower()
        smb_disabled = ("0x0" in smb_text) or ("the system was unable to find the specified registry value" in smb_text)
        results.append({
            "category": "Network Security",
            "check": "SMBv1 Disabled",
            "status": "PASS" if smb_disabled else "FAIL",
            "severity": "Critical",
            "details": "SMBv1 is disabled" if smb_disabled else "SMBv1 may be enabled (Vulnerable)"
        })
        return results

    def check_system_hardening(self):
        results = []
        # 5. Windows Defender Active
        res = self.execute_cmd("sc query WinDefend")
        defender_running = "running" in (res.get("stdout") or "").lower()
        results.append({
            "category": "System Hardening",
            "check": "Windows Defender Active",
            "status": "PASS" if defender_running else "FAIL",
            "severity": "High",
            "details": "Antivirus service is running" if defender_running else "Antivirus service is not running"
        })
        # 6. UAC Enabled
        res = self.execute_cmd("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin")
        out = res.get("stdout") or ""
        uac_val = ""
        for token in out.split():
            if token.startswith("0x"):
                uac_val = token
                break
        results.append({
            "category": "System Hardening",
            "check": "UAC Enabled",
            "status": "PASS" if uac_val and uac_val not in ["0x0"] else "FAIL",
            "severity": "High",
            "details": f"UAC Level: {uac_val}"
        })
        return results

    def check_services(self):
        results = []
        # 7. Service Telnet
        res = self.execute_cmd("sc query TlntSvr")
        results.append({
            "category": "Services",
            "check": "Service Telnet",
            "status": "FAIL" if "running" in (res.get("stdout") or "").lower() else "PASS",
            "severity": "Medium",
            "details": "Telnet is running" if "running" in (res.get("stdout") or "").lower() else "Telnet is not running"
        })
        # 8. Service FTP
        res = self.execute_cmd("sc query FTPSVC")
        results.append({
            "category": "Services",
            "check": "Service FTP",
            "status": "FAIL" if "running" in (res.get("stdout") or "").lower() else "PASS",
            "severity": "Medium",
            "details": "FTP is running" if "running" in (res.get("stdout") or "").lower() else "FTP is not running"
        })
        # 9. Service Print Spooler
        res = self.execute_cmd("sc query Spooler")
        spool_running = "running" in (res.get("stdout") or "").lower()
        results.append({
            "category": "Services",
            "check": "Service Print Spooler",
            "status": "WARNING" if spool_running else "PASS",
            "severity": "Medium",
            "details": "Spooler is running" if spool_running else "Spooler is stopped"
        })
        return results

    def check_logging(self):
        results = []
        # 10. Event Log Running
        res = self.execute_cmd("sc query EventLog")
        event_running = "running" in (res.get("stdout") or "").lower()
        results.append({
            "category": "Logging",
            "check": "Event Log Running",
            "status": "PASS" if event_running else "FAIL",
            "severity": "Medium",
            "details": "Event Log is active" if event_running else "Event Log is stopped"
        })
        return results
