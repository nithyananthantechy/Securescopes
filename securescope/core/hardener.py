from securescope.core.utils import logger, detect_platform
from securescope.hardeners.linux_hardener import LinuxHardener
from securescope.hardeners.windows_hardener import WindowsHardener

class SecureHardener:
    def __init__(self, auto_confirm=False, target_host=None, target_port=22, username=None, password=None, target_type=None):
        self.auto_confirm = auto_confirm
        self.hardener = None
        self.ssh_client = None

        if target_host and target_host != "localhost" and target_type == "linux":
            import paramiko
            logger.info(f"Connecting to {target_host} for remote hardening...")
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                self.ssh_client.connect(target_host, port=int(target_port or 22), username=username, password=password, timeout=10)
                self.hardener = LinuxHardener(ssh=self.ssh_client)
            except Exception as e:
                logger.error(f"Failed to connect for remote hardening: {e}")
                self.hardener = None
        else:
            self.plat_info = detect_platform()
            if "Linux" in self.plat_info["os"]:
                self.hardener = LinuxHardener()
            elif "Windows" in self.plat_info["os"]:
                self.hardener = WindowsHardener()

    def apply_fixes(self, scan_results):
        if not self.hardener:
            logger.error("No hardener available for this platform.")
            return []

        harden_log = []
        for result in scan_results:
            if result["status"] == "FAIL":
                fix_func = self.map_fix(result["check"])
                if fix_func:
                    if self.auto_confirm or self.ask_confirmation(result["check"]):
                        success, message = fix_func()
                        harden_log.append({
                            "check": result["check"],
                            "success": success,
                            "message": message
                        })
                        logger.info(f"Fix applied for {result['check']}: {message}")
        
        if self.ssh_client:
            self.ssh_client.close()
            
        return harden_log

    def map_fix(self, check_name):
        """Map a check name to a fix function."""
        mapping = {
            # Linux
            "Root login disabled": getattr(self.hardener, "fix_ssh_root_login", None),
            "Password auth disabled": getattr(self.hardener, "fix_ssh_password_auth", None),
            "UFW Active": getattr(self.hardener, "fix_ufw_enable", None),
            "Fail2ban Running": getattr(self.hardener, "fix_fail2ban", None),
            "No empty password accounts": getattr(self.hardener, "fix_empty_passwords", None),
            
            # Windows
            "SMBv1 Disabled": getattr(self.hardener, "fix_smb1", None),
            "Guest account disabled": getattr(self.hardener, "fix_guest_account", None),
            "Windows Firewall Status": getattr(self.hardener, "fix_firewall_enable", None),
        }
        return mapping.get(check_name)

    def ask_confirmation(self, check_name):
        # In CLI mode, this would be an input()
        # For now, we assume it's handled by the caller or auto_confirm
        return True
