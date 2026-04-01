from securescope.core.utils import run_command, logger

class WindowsHardener:
    def execute_ps(self, cmd):
        full_cmd = f"powershell.exe -ExecutionPolicy Bypass -Command \"{cmd}\""
        return run_command(full_cmd)

    def fix_smb1(self):
        logger.info("Disabling SMBv1...")
        cmd = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
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
        return False, f"Failed to enable Firewall: {res['stderr']}"

    def fix_windows_update(self):
        logger.info("Enabling automatic Windows updates...")
        # Placeholder for complex update management via PS
        cmd = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate' -Value 0"
        res = self.execute_ps(cmd)
        if res["success"]:
            return True, "Windows Update enabled."
        return False, "Failed to enable Windows Update."
