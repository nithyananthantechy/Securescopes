import json
from securescope.core.utils import run_command, logger

class DockerScanner:
    def __init__(self):
        self.category = "Container Security"

    def run_all_checks(self):
        checks = []
        # Check if Docker is installed and running
        res = run_command("docker info --format '{{json .}}'")
        if not res["success"]:
            checks.append({
                "category": self.category,
                "check": "Docker Daemon",
                "status": "PASS",
                "severity": "Low",
                "details": "Docker is not installed or not running (N/A)"
            })
            return checks

        checks.append({
            "category": self.category,
            "check": "Docker Daemon",
            "status": "PASS",
            "severity": "Low",
            "details": "Docker daemon is active"
        })

        # Check for containers running as root
        res_root = run_command("docker ps -q | xargs -I {} docker inspect --format '{{.State.Running}} {{.Config.User}}' {}")
        if res_root["success"]:
            root_containers = 0
            for line in res_root["stdout"].splitlines():
                if line.startswith("true") and (len(line.split()) < 2 or line.split()[1] == "" or line.split()[1] == "root" or line.split()[1] == "0"):
                    root_containers += 1
            if root_containers > 0:
                checks.append({
                    "category": self.category,
                    "check": "Root Containers",
                    "status": "FAIL",
                    "severity": "High",
                    "details": f"Found {root_containers} container(s) running as root user. Use USER directive in Dockerfile."
                })
            else:
                checks.append({
                    "category": self.category,
                    "check": "Root Containers",
                    "status": "PASS",
                    "severity": "High",
                    "details": "No active containers are running as root"
                })

        # Check for exposed Docker socket
        res_sock = run_command("ss -xlp | grep docker.sock")
        if res_sock["success"] and "docker.sock" in res_sock["stdout"]:
            checks.append({
                "category": self.category,
                "check": "Exposed Docker Socket",
                "status": "WARNING",
                "severity": "Medium",
                "details": "Docker socket is active. Ensure it is not exposed to untrusted containers."
            })
        return checks

    def scan_remote(self, ssh):
        checks = []
        try:
            stdin, stdout, stderr = ssh.exec_command("docker info --format '{{json .}}'")
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                checks.append({
                    "category": self.category,
                    "check": "Docker Daemon",
                    "status": "PASS",
                    "severity": "Low",
                    "details": "Docker is not installed or not running on remote host (N/A)"
                })
                return checks
            
            checks.append({
                "category": self.category,
                "check": "Docker Daemon",
                "status": "PASS",
                "severity": "Low",
                "details": "Docker daemon is active"
            })

            # Check for containers running as root
            stdin, stdout, stderr = ssh.exec_command("docker ps -q | xargs -I {} docker inspect --format '{{.State.Running}} {{.Config.User}}' {}")
            out = stdout.read().decode().strip()
            root_containers = 0
            if out:
                for line in out.splitlines():
                    if line.startswith("true") and (len(line.split()) < 2 or line.split()[1] == "" or line.split()[1] == "root" or line.split()[1] == "0"):
                        root_containers += 1
            if root_containers > 0:
                checks.append({
                    "category": self.category,
                    "check": "Root Containers",
                    "status": "FAIL",
                    "severity": "High",
                    "details": f"Found {root_containers} container(s) running as root user. Use USER directive in Dockerfile."
                })
            else:
                checks.append({
                    "category": self.category,
                    "check": "Root Containers",
                    "status": "PASS",
                    "severity": "High",
                    "details": "No active containers are running as root"
                })

            # Check for exposed Docker socket
            stdin, stdout, stderr = ssh.exec_command("ss -xlp | grep docker.sock")
            out = stdout.read().decode().strip()
            if "docker.sock" in out:
                checks.append({
                    "category": self.category,
                    "check": "Exposed Docker Socket",
                    "status": "WARNING",
                    "severity": "Medium",
                    "details": "Docker socket is active. Ensure it is not exposed to untrusted containers."
                })
        except Exception as e:
            logger.error(f"Docker remote scan failed: {str(e)}")
            checks.append({
                "category": self.category, "check": "Remote Execution",
                "status": "FAIL", "severity": "High", "details": str(e)
            })
            
        return checks
