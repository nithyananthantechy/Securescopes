import os
from securescope.core.utils import run_command, logger

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
        results = []
        results.extend(self.check_ssh())
        results.extend(self.check_firewall())
        results.extend(self.check_users())
        results.extend(self.check_filesystem())
        results.extend(self.check_services())
        results.extend(self.check_updates())
        results.extend(self.check_logging())
        return results

    def scan_remote(self, ssh_client):
        """Dedicated remote scan logic with individual error handling (FIX 1)."""
        checks = []
        
        def run_ssh(command):
            try:
                stdin, stdout, stderr = ssh_client.exec_command(command, timeout=30)
                return stdout.read().decode('utf-8', errors='ignore').strip()
            except:
                return ""

        # CHECK 1 - SSH Root login
        try:
            result = run_ssh("grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null")
            status = "PASS" if "no" in result.lower() else "FAIL"
            checks.append({
                "category": "SSH",
                "check": "Root login disabled",
                "status": status,
                "severity": "Critical",
                "details": result or "Not configured"
            })
        except: pass

        # CHECK 2 - Password Auth
        try:
            result = run_ssh("grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
            status = "PASS" if "no" in result.lower() else "FAIL"
            checks.append({
                "category": "SSH",
                "check": "Password auth disabled",
                "status": status,
                "severity": "Critical",
                "details": result or "Not configured"
            })
        except: pass

        # CHECK 3 - Firewall
        try:
            result = run_ssh("ufw status 2>/dev/null || iptables -L 2>/dev/null | head -5")
            status = "PASS" if "active" in result.lower() or "chain" in result.lower() else "FAIL"
            checks.append({
                "category": "Firewall",
                "check": "Firewall active",
                "status": status,
                "severity": "Critical",
                "details": result[:100] if result else "Not detected"
            })
        except: pass

        # CHECK 4 - Root only UID 0
        try:
            result = run_ssh("awk -F: '($3==0){print $1}' /etc/passwd")
            status = "PASS" if result.strip() == "root" else "FAIL"
            users_list = result.replace('\n', ', ')
            checks.append({
                "category": "Users",
                "check": "Only root has UID 0",
                "status": status,
                "severity": "Critical",
                "details": f"UID 0 users: {users_list}"
            })
        except: pass

        # CHECK 5 - Empty passwords
        try:
            result = run_ssh("sudo awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null")
            status = "PASS" if not result.strip() else "FAIL"
            checks.append({
                "category": "Users",
                "check": "No empty passwords",
                "status": status,
                "severity": "Critical",
                "details": result or "No empty passwords"
            })
        except: pass

        # CHECK 6 - Updates available
        try:
            result = run_ssh("apt list --upgradable 2>/dev/null | wc -l")
            count = int(result.strip()) - 1 if result.strip().isdigit() else 0
            status = "PASS" if count == 0 else "FAIL"
            checks.append({
                "category": "Updates",
                "check": "System up to date",
                "status": status,
                "severity": "High",
                "details": f"{count} updates pending"
            })
        except: pass

        # CHECK 7 - fail2ban
        try:
            result = run_ssh("systemctl is-active fail2ban 2>/dev/null")
            status = "PASS" if "active" in result else "FAIL"
            checks.append({
                "category": "Firewall",
                "check": "fail2ban running",
                "status": status,
                "severity": "High",
                "details": f"fail2ban: {result}"
            })
        except: pass

        # CHECK 8 - Unattended upgrades
        try:
            result = run_ssh("dpkg -l unattended-upgrades 2>/dev/null | grep ii")
            status = "PASS" if "ii" in result else "FAIL"
            checks.append({
                "category": "Updates",
                "check": "Auto updates enabled",
                "status": status,
                "severity": "Medium",
                "details": result or "Not installed"
            })
        except: pass

        # CHECK 9 - World writable dirs
        try:
            result = run_ssh("find /tmp /var /etc -maxdepth 2 -perm -o+w -type d 2>/dev/null | head -5")
            status = "PASS" if not result.strip() else "WARNING"
            checks.append({
                "category": "Filesystem",
                "check": "World-writable dirs",
                "status": status,
                "severity": "Medium",
                "details": result or "None found"
            })
        except: pass

        # CHECK 10 - Syslog running
        try:
            result = run_ssh("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null")
            status = "PASS" if "active" in result else "FAIL"
            checks.append({
                "category": "Logging",
                "check": "Syslog running",
                "status": status,
                "severity": "Medium",
                "details": f"Syslog: {result}"
            })
        except: pass

        return checks

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
            checks.append({"category": "SSH", "check": description, "status": status, "severity": severity, "details": details})
        check_config("PermitRootLogin", "no", "Root login disabled")
        check_config("PasswordAuthentication", "no", "Password auth disabled")
        check_config("MaxAuthTries", "3", "MaxAuthTries <= 3")
        check_config("Protocol", "2", "Protocol 2 only", severity="High")
        return checks

    def check_firewall(self):
        checks = []
        res = self.execute("ufw status")
        status = "PASS" if "Status: active" in res["stdout"] else "FAIL"
        checks.append({"category": "Firewall", "check": "UFW Active", "status": status, "severity": "Critical", "details": res["stdout"] if res["success"] else "UFW not found"})
        return checks

    def check_users(self):
        checks = []
        res = self.execute("awk -F: '$3 == 0 { print $1 }' /etc/passwd")
        users = res["stdout"].split('\n')
        status = "PASS" if len(users) == 1 and users[0] == "root" else "FAIL"
        checks.append({"category": "Users", "check": "Only root has UID 0", "status": status, "severity": "High", "details": f"Users: {', '.join(users)}"})
        return checks

    def check_filesystem(self):
        checks = []
        res = self.execute("find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -5")
        status = "PASS" if not res["stdout"] else "WARNING"
        checks.append({"category": "Filesystem", "check": "World-writable directories", "status": status, "severity": "High", "details": res["stdout"] or "No issues found"})
        return checks

    def check_services(self):
        checks = []
        bad_services = ["telnet", "ftp", "rsh", "rlogin"]
        found = []
        for svc in bad_services:
            res = self.execute(f"systemctl is-active {svc}")
            if res["stdout"] == "active": found.append(svc)
        status = "PASS" if not found else "FAIL"
        checks.append({"category": "Services", "check": "Unnecessary services", "status": status, "severity": "Medium", "details": f"Active risky: {', '.join(found)}" if found else "None"})
        return checks

    def check_updates(self):
        checks = []
        res = self.execute("apt-get -s upgrade | grep -P '^\d+ upgraded' | cut -d' ' -f1")
        count = res["stdout"] if res["success"] and res["stdout"] else "0"
        status = "PASS" if count == "0" else "WARNING"
        checks.append({"category": "Updates", "check": "System updates", "status": status, "severity": "Medium", "details": f"{count} pending"})
        return checks

    def check_logging(self):
        checks = []
        res = self.execute("systemctl is-active rsyslog")
        status = "PASS" if res["stdout"] == "active" else "FAIL"
        checks.append({"category": "Logging", "check": "Syslog Running", "status": status, "severity": "Medium", "details": "rsyslog is active" if status == "PASS" else "rsyslog inactive"})
        return checks
