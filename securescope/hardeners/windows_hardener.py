from securescope.core.utils import run_command, logger

class WindowsHardener:
    def __init__(self, target_host="local", winrm_client=None):
        self.target_host = target_host
        self.winrm_client = winrm_client

    def execute_ps(self, cmd):
        if self.target_host == "local":
            import base64
            encoded_cmd = base64.b64encode(cmd.encode('utf-16le')).decode('utf-8')
            full_cmd = f"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process powershell -ArgumentList '-WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}' -Verb RunAs -Wait\""
            res = run_command(full_cmd)
            if res["success"]:
                return {"success": True, "stdout": "", "stderr": ""}
            return res
        elif self.winrm_client:
            try:
                res = self.winrm_client.run_ps(cmd)
                return {
                    "stdout": res.std_out.decode('utf-8', errors='ignore').strip(),
                    "stderr": res.std_err.decode('utf-8', errors='ignore').strip(),
                    "success": res.status_code == 0
                }
            except Exception as e:
                logger.error(f"WinRM PS Hardening failed: {str(e)}")
                return {"stdout": "", "stderr": str(e), "success": False}
        return {"stdout": "", "stderr": "Remote not implemented", "success": False}

    def fix_smb1(self):
        logger.info("Disabling SMBv1...")
        cmd = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -Value 0 -Type DWord -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "SMBv1 disabled successfully."
        return False, f"Failed to disable SMBv1: {res['stderr']}"

    def fix_guest_account(self):
        logger.info("Disabling Guest account...")
        cmd = "Disable-LocalUser -Name Guest"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Guest account disabled."
        return False, f"Failed to disable Guest account: {res['stderr']}"

    def fix_firewall_enable(self):
        logger.info("Enabling all Windows Firewall profiles...")
        cmd = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "All Firewall profiles enabled."
        err_msg = res['stderr'] if res['stderr'] else res['stdout']
        return False, f"Failed to enable Firewall: {err_msg}"

    def fix_default_admin(self):
        logger.info("Disabling Default Administrator account...")
        cmd = "Disable-LocalUser -Name Administrator"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Default Admin account disabled."
        return False, f"Failed to disable Default Admin: {res['stderr']}"

    def fix_defender_active(self):
        logger.info("Enabling Windows Defender...")
        cmd = "Start-Service WinDefend; Set-Service WinDefend -StartupType Automatic"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Windows Defender activated."
        return False, f"Failed to activate Defender: {res['stderr']}"

    def fix_uac_enabled(self):
        logger.info("Enabling UAC...")
        cmd = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord -Force"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "UAC enabled."
        return False, f"Failed to enable UAC: {res['stderr']}"

    def fix_service_telnet(self):
        logger.info("Disabling Telnet service...")
        cmd = "Stop-Service TlntSvr -Force -ErrorAction SilentlyContinue; Set-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Telnet service disabled."
        return False, f"Failed to disable Telnet: {res['stderr']}"

    def fix_service_ftp(self):
        logger.info("Disabling FTP service...")
        cmd = "Stop-Service FTPSVC -Force -ErrorAction SilentlyContinue; Set-Service FTPSVC -StartupType Disabled -ErrorAction SilentlyContinue"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "FTP service disabled."
        return False, f"Failed to disable FTP: {res['stderr']}"

    def fix_service_spooler(self):
        logger.info("Disabling Print Spooler service...")
        cmd = "Stop-Service Spooler -Force -ErrorAction SilentlyContinue; Set-Service Spooler -StartupType Disabled -ErrorAction SilentlyContinue"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Print Spooler service disabled."
        return False, f"Failed to disable Print Spooler: {res['stderr']}"

    def fix_event_log(self):
        logger.info("Enabling Event Log service...")
        cmd = "Set-Service EventLog -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service EventLog -ErrorAction SilentlyContinue"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Event Log service activated."
        return False, f"Failed to activate Event Log: {res['stderr']}"
