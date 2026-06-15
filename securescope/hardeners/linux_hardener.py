import os
import shutil
import time
from securescope.core.utils import run_command, logger

class LinuxHardener:
    def __init__(self, ssh=None, username=None, password=None):
        self.ssh = ssh
        self.username = username
        self.password = password
        self.backup_dir = os.path.expanduser("~/.securescope/backups/")
        if not self.ssh and not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def execute_cmd(self, cmd, **kwargs):
        if self.ssh and getattr(self, 'username', None) != 'root' and getattr(self, 'password', None):
            cmd = f"echo '{self.password}' | sudo -S {cmd}"
        from securescope.core.utils import run_command
        return run_command(cmd, ssh=self.ssh)

    def backup_file(self, file_path):
        timestamp = int(time.time())
        filename = os.path.basename(file_path)
        if self.ssh:
            backup_path = f"/tmp/{filename}.{timestamp}.bak"
            self.execute_cmd(f"cp {file_path} {backup_path}", ssh=self.ssh)
            logger.info(f"Remote backup created: {backup_path}")
            return backup_path
        else:
            if not os.path.exists(file_path):
                return None
            backup_path = os.path.join(self.backup_dir, f"{filename}.{timestamp}")
            shutil.copy2(file_path, backup_path)
            logger.info(f"Local backup created: {backup_path}")
            return backup_path

    def fix_ssh_root_login(self):
        config_path = "/etc/ssh/sshd_config"
        self.backup_file(config_path)
        logger.info("Disabling SSH root login...")
        cmd = "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            self.execute_cmd("systemctl restart ssh", ssh=self.ssh)
            return True, "Root login disabled."
        return False, f"Failed to disable root login: {res['stderr']}"

    def fix_ssh_password_auth(self):
        config_path = "/etc/ssh/sshd_config"
        self.backup_file(config_path)
        logger.info("Disabling SSH password authentication...")
        cmd = "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            self.execute_cmd("systemctl restart ssh", ssh=self.ssh)
            return True, "Password authentication disabled."
        return False, f"Failed to disable password auth: {res['stderr']}"

    def fix_ufw_enable(self):
        logger.info("Enabling UFW with default deny...")
        self.execute_cmd("ufw default deny incoming", ssh=self.ssh)
        self.execute_cmd("ufw allow ssh", ssh=self.ssh) # Critical to not lock self out
        res = self.execute_cmd("ufw --force enable", ssh=self.ssh)
        if res["success"]:
            return True, "UFW enabled and configured."
        return False, f"Failed to enable UFW: {res['stderr']}"

    def fix_fail2ban(self):
        logger.info("Installing and enabling fail2ban...")
        self.execute_cmd("apt-get update", ssh=self.ssh)
        res = self.execute_cmd("apt-get install -y fail2ban", ssh=self.ssh)
        if res["success"]:
            self.execute_cmd("systemctl enable --now fail2ban", ssh=self.ssh)
            return True, "fail2ban installed and active."
        return False, f"Failed to install fail2ban: {res['stderr']}"

    def fix_empty_passwords(self):
        logger.info("Locking accounts with empty passwords...")
        res = self.execute_cmd("awk -F: '($2 == \"\") { print $1 }' /etc/shadow", ssh=self.ssh)
        if res["stdout"]:
            users = res["stdout"].split('\n')
            for user in users:
                if user.strip():
                    self.execute_cmd(f"passwd -l {user.strip()}", ssh=self.ssh)
            return True, f"Locked {len(users)} accounts."
        return True, "No empty passwords found."

    def fix_tmp_noexec(self):
        logger.info("Remounting /tmp with noexec...")
        res = self.execute_cmd("mount -o remount,noexec /tmp", ssh=self.ssh)
        if res["success"]:
            return True, "/tmp remounted with noexec."
        return False, "Failed to remount /tmp."

    def fix_ssh_protocol(self):
        self.backup_file("/etc/ssh/sshd_config")
        logger.info("Enforcing SSH Protocol 2...")
        cmd = "sed -i '/^Protocol/d' /etc/ssh/sshd_config; bash -c \"echo 'Protocol 2' >> /etc/ssh/sshd_config\"; systemctl restart ssh"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "SSH Protocol 2 enforced."
        return False, f"Failed to enforce Protocol 2: {res['stderr']}"

    def fix_ssh_max_auth(self):
        self.backup_file("/etc/ssh/sshd_config")
        logger.info("Enforcing MaxAuthTries 3...")
        cmd = "sed -i '/^MaxAuthTries/d' /etc/ssh/sshd_config; bash -c \"echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config\"; systemctl restart ssh"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "SSH MaxAuthTries set to 3."
        return False, f"Failed to set MaxAuthTries: {res['stderr']}"

    def fix_uid_0(self):
        logger.info("Locking non-root UID 0 accounts...")
        res = self.execute_cmd("awk -F: '$3 == 0 && $1 != \"root\" { print $1 }' /etc/passwd", ssh=self.ssh)
        if res["stdout"]:
            users = res["stdout"].split('\n')
            for user in users:
                if user.strip():
                    self.execute_cmd(f"passwd -l {user.strip()}", ssh=self.ssh)
            return True, f"Locked {len(users)} non-root UID 0 accounts."
        return True, "No non-root UID 0 accounts found."

    def fix_world_writable(self):
        logger.info("Adding sticky bit to world-writable directories...")
        cmd = "find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null -exec chmod a+t {} +"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "Sticky bit applied to world-writable directories."
        return False, f"Failed to apply sticky bit: {res['stderr']}"

    def fix_unnecessary_services(self):
        logger.info("Disabling unnecessary services...")
        cmd = "systemctl disable --now telnet ftp rsh rlogin 2>/dev/null || true"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "Unnecessary services disabled."
        return False, f"Failed to disable services: {res['stderr']}"

    def fix_system_updates(self):
        logger.info("Applying system updates...")
        cmd = "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "System updates applied."
        return False, f"Failed to apply updates: {res['stderr']}"

    def fix_syslog(self):
        logger.info("Enabling rsyslog...")
        cmd = "apt-get install -y rsyslog && systemctl enable --now rsyslog"
        res = self.execute_cmd(cmd, ssh=self.ssh)
        if res["success"]:
            return True, "rsyslog enabled."
        return False, f"Failed to enable rsyslog: {res['stderr']}"
