import paramiko
from securescope.core.utils import logger

class NetworkScanner:
    def __init__(self, host, user, password, device_type="cisco"):
        self.host = host
        self.user = user
        self.password = password
        self.device_type = device_type
        self.client = None

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.user, password=self.password, timeout=10)
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {str(e)}")
            return False

    def execute(self, cmd):
        if not self.client: return ""
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=12)
        # Wait for remote command completion without fixed sleep delay.
        stdout.channel.recv_exit_status()
        return stdout.read().decode(errors="ignore").strip()

    def run_all_checks(self):
        if not self.connect():
            return [{
                "category": "Network",
                "check": "Connection",
                "status": "FAIL",
                "severity": "Critical",
                "details": f"Could not connect to {self.host}"
            }]

        results = []
        results.extend(self.check_ssh_version())
        results.extend(self.check_telnet_disabled())
        results.extend(self.check_snmp_config())
        results.extend(self.check_password_encryption())
        
        self.client.close()
        return results

    def check_ssh_version(self):
        checks = []
        # Check SSH version (Cisco IOS)
        output = self.execute("show ip ssh")
        status = "PASS" if "SSH v2" in output else "FAIL"
        checks.append({
            "category": "Network",
            "check": "SSH Version",
            "status": status,
            "severity": "High",
            "details": f"Found: {output[:100]}..." if output else "No SSH info found"
        })
        return checks

    def check_telnet_disabled(self):
        checks = []
        # Telnet should not be running
        output = self.execute("show run | include telnet")
        status = "FAIL" if "telnet" in output.lower() else "PASS"
        checks.append({
            "category": "Network",
            "check": "Telnet Disabled",
            "status": status,
            "severity": "Critical",
            "details": "Telnet service might be active" if status == "FAIL" else "Telnet is disabled"
        })
        return checks

    def check_snmp_config(self):
        checks = []
        output = self.execute("show run | include snmp-server community")
        status = "FAIL" if "public" in output.lower() or "private" in output.lower() else "PASS"
        checks.append({
            "category": "Network",
            "check": "SNMP Community",
            "status": status,
            "severity": "Critical",
            "details": "Default SNMP communities detected" if status == "FAIL" else "No default SNMP communities found"
        })
        return checks

    def check_password_encryption(self):
        checks = []
        output = self.execute("show run | include password-encryption")
        status = "PASS" if "service password-encryption" in output.lower() else "FAIL"
        checks.append({
            "category": "Network",
            "check": "Password Encryption",
            "status": status,
            "severity": "Medium",
            "details": "Password encryption is active" if status == "PASS" else "Password encryption is disabled"
        })
        return checks
