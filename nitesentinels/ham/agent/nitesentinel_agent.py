"""
NiteSentinel Standalone Endpoint Telemetry Agent
================================================
A lightweight, zero-dependency Python agent for automated hardware discovery
and continuous health telemetry.

Key Design Principles:
  - 100% Optional: NiteSentinel operates fully without this agent.
  - Zero Dependencies: Uses only Python 3.8+ standard library.
  - Cross-Platform: Works on Linux, macOS, and Windows.
  - Low Overhead: Runs periodically, consumes < 15MB RAM and < 0.1% CPU.
  - Secure: Uses TLS and bearer token authentication.

Usage:
  python nitesentinel_agent.py --server https://sentinel.corp.local --token ENROLL_TOKEN
  python nitesentinel_agent.py --oneshot
  python nitesentinel_agent.py --daemon --interval 300
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("NiteSentinelAgent")


def get_system_telemetry() -> dict[str, Any]:
    """Collect hardware and system telemetry using Python standard library."""
    hostname = socket.gethostname()
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    arch = platform.machine()
    processor = platform.processor() or arch

    # CPU cores
    cpu_cores = os.cpu_count() or 1

    # Memory & Disk info
    ram_gb: float = 0.0
    disk_gb: float = 0.0
    disk_used_percent: float = 0.0

    # Disk usage from shutil if available
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        disk_gb = round(total / (1024 ** 3), 1)
        disk_used_percent = round((used / total) * 100, 1)
    except Exception:
        pass

    # RAM discovery
    if os_name == "Windows":
        try:
            cmd = "wmic computersystem get TotalPhysicalMemory /Value"
            output = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
            for line in output.splitlines():
                if "TotalPhysicalMemory=" in line:
                    bytes_val = int(line.split("=")[1].strip())
                    ram_gb = round(bytes_val / (1024 ** 3), 1)
        except Exception:
            pass
    elif os_name == "Linux":
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        ram_gb = round(kb / (1024 ** 2), 1)
                        break
        except Exception:
            pass
    elif os_name == "Darwin":
        try:
            output = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=5)
            ram_gb = round(int(output.strip()) / (1024 ** 3), 1)
        except Exception:
            pass

    # Primary IP & MAC addresses
    ip_address = ""
    mac_address = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"

    try:
        import uuid
        mac_num = uuid.getnode()
        mac_address = ":".join(f"{(mac_num >> (i * 8)) & 0xff:02x}" for i in reversed(range(6)))
    except Exception:
        mac_address = ""

    return {
        "hostname": hostname,
        "platform": f"{os_name} {os_release} ({arch})",
        "operating_system": os_name,
        "os_version": os_version,
        "architecture": arch,
        "cpu": f"{processor} ({cpu_cores} cores)",
        "ram": f"{ram_gb} GB" if ram_gb else "Unknown",
        "storage": f"{disk_gb} GB ({disk_used_percent}% used)" if disk_gb else "Unknown",
        "disk_percent": disk_used_percent,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def send_http(url: str, payload: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    """Send JSON payload over HTTP/HTTPS with proper timeouts and headers."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    ctx = ssl.create_default_context()
    # Allow insecure for local self-signed lab environments if env set
    if os.environ.get("NITESENTINEL_INSECURE_SSL") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
        res_body = response.read().decode("utf-8")
        return json.loads(res_body) if res_body else {}


def main():
    parser = argparse.ArgumentParser(description="NiteSentinel Endpoint Telemetry Agent")
    parser.add_argument("--server", default=os.environ.get("NITESENTINEL_SERVER", "http://localhost:8080"), help="NiteSentinel server URL")
    parser.add_argument("--token", default=os.environ.get("NITESENTINEL_TOKEN"), help="Agent registration token or bearer token")
    parser.add_argument("--agent-id", default=os.environ.get("NITESENTINEL_AGENT_ID"), help="Existing enrolled Agent ID")
    parser.add_argument("--oneshot", action="store_true", help="Send telemetry once and exit")
    parser.add_argument("--daemon", action="store_true", help="Run indefinitely in background")
    parser.add_argument("--interval", type=int, default=300, help="Check-in interval in seconds (default: 300)")

    args = parser.parse_args()

    server = args.server.rstrip("/")
    logger.info("NiteSentinel Telemetry Agent initializing...")
    logger.info("Target Server: %s", server)

    telemetry = get_system_telemetry()
    logger.info("Detected Endpoint: %s [%s] IP: %s MAC: %s", telemetry["hostname"], telemetry["platform"], telemetry["ip_address"], telemetry["mac_address"])

    if args.oneshot or not args.daemon:
        endpoint = f"{server}/api/ham/agents/checkin"
        logger.info("Sending one-shot checkin to %s...", endpoint)
        try:
            resp = send_http(endpoint, telemetry, token=args.token)
            logger.info("Checkin response: %s", resp)
        except Exception as e:
            logger.error("Checkin failed: %s", e)
            sys.exit(1)
        return

    logger.info("Starting background daemon. Heartbeat interval: %ds", args.interval)
    while True:
        try:
            t = get_system_telemetry()
            endpoint = f"{server}/api/ham/agents/checkin"
            send_http(endpoint, t, token=args.token)
            logger.info("Heartbeat checkin successful (%s)", t["timestamp"])
        except Exception as e:
            logger.warning("Heartbeat checkin error: %s", e)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
