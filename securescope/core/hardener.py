from securescope.core.utils import logger, detect_platform
from securescope.hardeners.linux_hardener import LinuxHardener
from securescope.hardeners.windows_hardener import WindowsHardener

class SecureHardener:
    def __init__(self, auto_confirm=False, target_host=None, target_port=22, username=None, password=None, target_type=None):
        import socket
        local_ips = ["127.0.0.1", "localhost", "::1"]
        try:
            hostname = socket.gethostname()
            _, _, ips = socket.gethostbyname_ex(hostname)
            local_ips.extend(ips)
        except Exception:
            pass
        if target_host in local_ips:
            target_host = "local"
            
        self.auto_confirm = auto_confirm
        self.hardener = None
        self.ssh_client = None

        if target_host and target_host != "local":
            try:
                if target_type == "linux":
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target_host, port=target_port, username=username, password=password, timeout=5)
                    self.ssh_client = ssh
                    self.hardener = LinuxHardener(ssh=ssh, username=username, password=password)
                elif target_type == "windows":
                    import winrm
                    session = winrm.Session(
                        f'http://{target_host}:{target_port}/wsman',
                        auth=(username, password),
                        transport='ntlm',
                        server_cert_validation='ignore'
                    )
                    self.hardener = WindowsHardener(target_host=target_host, winrm_client=session)
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
            # Linux (10 checks)
            "Root login disabled": getattr(self.hardener, "fix_ssh_root_login", None),
            "Password auth disabled": getattr(self.hardener, "fix_ssh_password_auth", None),
            "MaxAuthTries <= 3": getattr(self.hardener, "fix_ssh_max_auth", None),
            "Protocol 2 only": getattr(self.hardener, "fix_ssh_protocol", None),
            "UFW Active": getattr(self.hardener, "fix_ufw_enable", None),
            "Only root has UID 0": getattr(self.hardener, "fix_uid_0", None),
            "World-writable directories": getattr(self.hardener, "fix_world_writable", None),
            "Unnecessary services": getattr(self.hardener, "fix_unnecessary_services", None),
            "System updates": getattr(self.hardener, "fix_system_updates", None),
            "Syslog Running": getattr(self.hardener, "fix_syslog", None),
            
            # Windows (10 checks)
            "Guest account disabled": getattr(self.hardener, "fix_guest_account", None),
            "Default Admin disabled": getattr(self.hardener, "fix_default_admin", None),
            "Windows Firewall Status": getattr(self.hardener, "fix_firewall_enable", None),
            "SMBv1 Disabled": getattr(self.hardener, "fix_smb1", None),
            "Windows Defender Active": getattr(self.hardener, "fix_defender_active", None),
            "UAC Enabled": getattr(self.hardener, "fix_uac_enabled", None),
            "Service Telnet": getattr(self.hardener, "fix_service_telnet", None),
            "Service FTP": getattr(self.hardener, "fix_service_ftp", None),
            "Service Print Spooler": getattr(self.hardener, "fix_service_spooler", None),
            "Event Log Running": getattr(self.hardener, "fix_event_log", None),
        }
        return mapping.get(check_name)

    def ask_confirmation(self, check_name):
        # In CLI mode, this would be an input()
        # For now, we assume it's handled by the caller or auto_confirm
        return True
