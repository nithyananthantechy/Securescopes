import os
import platform
import subprocess
import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

# Global Console for rich output
console = Console()

def setup_logging(log_file="logs/securescope.log"):
    """Setup logging to both file and rich console."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    rotating = TimedRotatingFileHandler(log_file, when="midnight", backupCount=7, encoding="utf-8")
    rotating.setFormatter(logging.Formatter("%(asctime)s|%(levelname)s|%(name)s|%(message)s"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s|%(levelname)s|%(name)s|%(message)s",
        handlers=[
            rotating,
            RichHandler(rich_tracebacks=True, markup=True)
        ]
    )
    return logging.getLogger("securescope")

logger = setup_logging()

def get_platform_name():
    """Enhanced platform detection including Windows 11 and WSL2."""
    if platform.system() == 'Windows':
        try:
            build = int(platform.version().split('.')[-1])
            return 'Windows 11' if build >= 22000 else 'Windows 10'
        except:
            return 'Windows'
    
    # WSL Detection
    try:
        if os.path.exists('/proc/version'):
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    return 'WSL2'
    except:
        pass
        
    return platform.system()

def detect_platform():
    """Detect the current operating system and environment (WSL)."""
    plat_name = get_platform_name()
    return {
        "os": plat_name,
        "is_wsl": plat_name == 'WSL2',
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine()
    }

def run_command(command, shell=True, timeout=30, ssh=None):
    """Execute a shell command safely natively or over SSH."""
    if ssh:
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            status = stdout.channel.recv_exit_status()
            return {
                "stdout": out,
                "stderr": err,
                "returncode": status,
                "success": status == 0
            }
        except Exception as e:
            logger.error(f"SSH command failed: {command} -> {str(e)}")
            return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}
            
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return {"stdout": "", "stderr": "Timeout", "returncode": -1, "success": False}
    except Exception as e:
        logger.error(f"Error running command {command}: {str(e)}")
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}

def get_banner(plat_info):
    """Generate the SecureScope startup banner."""
    banner_content = [
        "[bold cyan]SecureScope v1.0 by NiTechSpark[/bold cyan]",
        f"[yellow]Platform: {plat_info['os']}[/yellow]",
        "[green]Mode: Local + Remote Scan Ready[/green]"
    ]
    return Panel("\n".join(banner_content), border_style="bold blue", expand=False)
