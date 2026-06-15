import os
from securescope.core.utils import run_command, logger
from concurrent.futures import ThreadPoolExecutor

class LinuxScanner:
    def __init__(self, target_host="local", ssh_client=None):
        self.target_host = target_host
        self.ssh_client = ssh_client # For remote scanning

    def execute(self, command):
        """Helper to run command locally or via SSH."""
        if self.target_host == "local":
            return run_command(command)
        else:
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=30)
                return {
                    "stdout": stdout.read().decode('utf-8', errors='ignore').strip(),
                    "stderr": stderr.read().decode('utf-8', errors='ignore').strip(),
                    "returncode": stdout.channel.recv_exit_status(),
                    "success": stdout.channel.recv_exit_status() == 0
                }
            except Exception as e:
                logger.error(f"SSH execution failed: {str(e)}")
                return {"stdout": "", "stderr": str(e), "success": False}

    def run_all_checks(self):
        """Main entry point for local scans."""
        checks = [
            self.check_ssh,
            self.check_firewall,
            self.check_users,
            self.check_filesystem,
            self.check_services,
            self.check_updates,
            self.check_logging,
        ]
        results = []
        # Run independent checks concurrently to reduce scan latency.
        with ThreadPoolExecutor(max_workers=min(7, len(checks))) as ex:
            futures = [ex.submit(fn) for fn in checks]
            for f in futures:
                results.extend(f.result())
        return results

    def check_ssh(self):
        checks = []
        sshd_config_path = "/etc/ssh/sshd_config"
        def check_config(param, expected, description, severity="Critical"):
            cmd = f"grep '^{param}' {sshd_config_path}"
            res = self.execute(cmd)
            status = "FAIL"
            details = f"Parameter {param} not found or mismatch."
            if res["success"]:
                if expected in res["stdout"]:
                    status = "PASS"
                    details = f"{param} is correctly set to {expected}"
                else:
                    details = f"Found: {res['stdout']}. Expected: {expected}"
            checks.append({"category": "SSH", "check": description, "status": status, "severity": severity, "details": details, "description": desc_text})
        check_config("PermitRootLogin", "no", "Root login disabled", desc_text="Direct SSH root login should be disabled to prevent brute-force attacks against the root account.")
        check_config("PasswordAuthentication", "no", "Password auth disabled", desc_text="Password authentication should be disabled in favor of key-based authentication to prevent credential guessing.")
        check_config("MaxAuthTries", "3", "MaxAuthTries <= 3", desc_text="Limiting the maximum number of authentication attempts thwarts brute-force guessing of SSH credentials.")
        check_config("Protocol", "2", "Protocol 2 only", severity="High", desc_text="SSH Protocol version 2 should be strictly enforced, as Protocol 1 has known cryptographic weaknesses.")
        return checks

    def check_firewall(self):
        checks = []
        res = self.execute("systemctl is-active ufw")
        status = "PASS" if res["stdout"] == "active" else "FAIL"
        checks.append({"category": "Firewall", "check": "UFW Active", "status": status, "severity": "Critical", "details": "UFW is active" if status == "PASS" else "UFW inactive or not found", "description": "An active Uncomplicated Firewall (UFW) prevents unauthorized inbound network connections to the system."})
        return checks

    def check_users(self):
        checks = []
        res = self.execute("awk -F: '$3 == 0 { print $1 }' /etc/passwd")
        users = res["stdout"].split('\n')
        status = "PASS" if len(users) == 1 and users[0] == "root" else "FAIL"
        checks.append({"category": "Users", "check": "Only root has UID 0", "status": status, "severity": "High", "details": f"Users: {', '.join(users)}", "description": "Accounts with a User ID (UID) of 0 have root privileges. Only the default root account should have this UID."})
        return checks

    def check_filesystem(self):
        checks = []
        res = self.execute("find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -5")
        status = "PASS" if not res["stdout"] else "WARNING"
        checks.append({"category": "Filesystem", "check": "World-writable directories", "status": status, "severity": "High", "details": res["stdout"] or "No issues found", "description": "World-writable directories without the sticky bit allow any user to delete or modify files, posing a privilege escalation risk."})
        return checks

    def check_services(self):
        checks = []
        bad_services = ["telnet", "ftp", "rsh", "rlogin"]
        found = []
        for svc in bad_services:
            res = self.execute(f"systemctl is-active {svc}")
            if res["stdout"] == "active": found.append(svc)
        status = "PASS" if not found else "FAIL"
        checks.append({"category": "Services", "check": "Unnecessary services", "status": status, "severity": "Medium", "details": f"Active risky: {', '.join(found)}" if found else "None", "description": "Legacy, unencrypted services like Telnet and FTP transmit passwords in cleartext and should be disabled."})
        return checks

    def check_updates(self):
        checks = []
        res = self.execute("apt-get -s upgrade | grep -P '^\d+ upgraded' | cut -d' ' -f1")
        count = res["stdout"] if res["success"] and res["stdout"] else "0"
        status = "PASS" if count == "0" else "WARNING"
        checks.append({"category": "Updates", "check": "System updates", "status": status, "severity": "Medium", "details": f"{count} pending", "description": "Unapplied system updates can leave the operating system vulnerable to known exploits."})
        return checks

    def check_logging(self):
        checks = []
        res = self.execute("systemctl is-active rsyslog")
        status = "PASS" if res["stdout"] == "active" else "FAIL"
        checks.append({"category": "Logging", "check": "Syslog Running", "status": status, "severity": "Medium", "details": "rsyslog is active" if status == "PASS" else "rsyslog inactive", "description": "The rsyslog service must be running to ensure security events, audits, and errors are properly logged."})
        return checks
