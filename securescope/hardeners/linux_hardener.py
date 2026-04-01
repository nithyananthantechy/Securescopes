import os
import shutil
import time
from securescope.core.utils import run_command, logger

class LinuxHardener:
    def __init__(self, ssh=None):
        self.ssh = ssh
        self.backup_dir = os.path.expanduser("~/.securescope/backups/")
        if not self.ssh and not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def backup_file(self, file_path):
        timestamp = int(time.time())
        filename = os.path.basename(file_path)
        if self.ssh:
            backup_path = f"/tmp/{filename}.{timestamp}.bak"
            run_command(f"cp {file_path} {backup_path}", ssh=self.ssh)
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
        res = run_command(cmd, ssh=self.ssh)
        if res["success"]:
            run_command("systemctl restart ssh", ssh=self.ssh)
            return True, "Root login disabled."
        return False, f"Failed to disable root login: {res['stderr']}"

    def fix_ssh_password_auth(self):
        config_path = "/etc/ssh/sshd_config"
        self.backup_file(config_path)
        logger.info("Disabling SSH password authentication...")
        cmd = "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
        res = run_command(cmd, ssh=self.ssh)
        if res["success"]:
            run_command("systemctl restart ssh", ssh=self.ssh)
            return True, "Password authentication disabled."
        return False, f"Failed to disable password auth: {res['stderr']}"

    def fix_ufw_enable(self):
        logger.info("Enabling UFW with default deny...")
        run_command("ufw default deny incoming", ssh=self.ssh)
        run_command("ufw allow ssh", ssh=self.ssh) # Critical to not lock self out
        res = run_command("ufw --force enable", ssh=self.ssh)
        if res["success"]:
            return True, "UFW enabled and configured."
        return False, f"Failed to enable UFW: {res['stderr']}"

    def fix_fail2ban(self):
        logger.info("Installing and enabling fail2ban...")
        run_command("apt-get update", ssh=self.ssh)
        res = run_command("apt-get install -y fail2ban", ssh=self.ssh)
        if res["success"]:
            run_command("systemctl enable --now fail2ban", ssh=self.ssh)
            return True, "fail2ban installed and active."
        return False, f"Failed to install fail2ban: {res['stderr']}"

    def fix_empty_passwords(self):
        logger.info("Locking accounts with empty passwords...")
        res = run_command("awk -F: '($2 == \"\") { print $1 }' /etc/shadow", ssh=self.ssh)
        if res["stdout"]:
            users = res["stdout"].split('\n')
            for user in users:
                if user.strip():
                    run_command(f"passwd -l {user.strip()}", ssh=self.ssh)
            return True, f"Locked {len(users)} accounts."
        return True, "No empty passwords found."

    def fix_tmp_noexec(self):
        logger.info("Remounting /tmp with noexec...")
        res = run_command("mount -o remount,noexec /tmp", ssh=self.ssh)
        if res["success"]:
            return True, "/tmp remounted with noexec."
        return False, "Failed to remount /tmp."
