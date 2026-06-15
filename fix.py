import sys
fpath = r'c:\Users\Nithyananthan\NITECHSPARK\NiteSentinels\securescope\hardeners\linux_hardener.py'
with open(fpath, 'r') as f:
    code = f.read()

# Replace init
old_init = "def __init__(self, ssh=None):\n        self.ssh = ssh"
new_init = "def __init__(self, ssh=None, username=None, password=None):\n        self.ssh = ssh\n        self.username = username\n        self.password = password"
code = code.replace(old_init, new_init)

# Replace backup_file so we can prepend execute_cmd
helper = """    def execute_cmd(self, cmd, **kwargs):
        if self.ssh and getattr(self, 'username', None) != 'root' and getattr(self, 'password', None):
            cmd = f"echo '{self.password}' | sudo -S {cmd}"
        from securescope.core.utils import run_command
        return run_command(cmd, ssh=self.ssh)

    def backup_file"""
code = code.replace("    def backup_file", helper)

# Replace run_command inside the class methods
parts = code.split("    def backup_file")
parts[1] = parts[1].replace("run_command(", "self.execute_cmd(")
code = "    def backup_file".join(parts)

with open(fpath, 'w') as f:
    f.write(code)
print("done")
