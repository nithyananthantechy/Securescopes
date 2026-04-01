import socket
import concurrent.futures
from securescope.core.utils import logger

# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
}

# Risky ports that shouldn't be open
RISKY_PORTS = {
    21: ("FTP is unencrypted — use SFTP instead", "High"),
    23: ("Telnet is unencrypted — use SSH instead", "Critical"),
    25: ("SMTP open — potential spam relay", "Medium"),
    110: ("POP3 unencrypted — use POP3S", "Medium"),
    111: ("RPCBind exposed — common attack vector", "High"),
    135: ("MSRPC exposed — Windows exploit target", "High"),
    139: ("NetBIOS exposed — information disclosure", "High"),
    143: ("IMAP unencrypted — use IMAPS", "Medium"),
    445: ("SMB exposed — WannaCry/EternalBlue target", "Critical"),
    1433: ("MSSQL exposed — should not be public", "High"),
    3306: ("MySQL exposed — should not be public", "High"),
    3389: ("RDP exposed — brute force target", "Critical"),
    5432: ("PostgreSQL exposed — should not be public", "High"),
    5900: ("VNC exposed — often unencrypted", "High"),
    6379: ("Redis exposed — usually no auth", "Critical"),
    27017: ("MongoDB exposed — often no auth", "Critical"),
    9200: ("Elasticsearch exposed — no auth by default", "High"),
}


class PortScanner:
    def __init__(self, target_host, ports=None, timeout=1.5):
        self.target = target_host
        self.ports = ports or list(COMMON_PORTS.keys())
        self.timeout = timeout

    def scan_port(self, port):
        """Scan a single port. Returns (port, is_open)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return (port, result == 0)
        except Exception:
            return (port, False)

    def run_scan(self):
        """Scan all ports concurrently and return open ports list."""
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = COMMON_PORTS.get(port, "Unknown")
                    open_ports.append({"port": port, "service": service})
        
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def run_all_checks(self):
        """Run port scan and generate security check results."""
        logger.info(f"Starting port scan on {self.target}...")
        checks = []
        open_ports = self.run_scan()
        
        if not open_ports:
            checks.append({
                "category": "Port Scan",
                "check": "Open Ports",
                "status": "PASS",
                "severity": "Low",
                "details": f"No common ports open on {self.target}"
            })
            return checks

        # Summary check
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in open_ports])
        checks.append({
            "category": "Port Scan",
            "check": "Open Ports Summary",
            "status": "WARNING" if len(open_ports) <= 5 else "FAIL",
            "severity": "Medium",
            "details": f"{len(open_ports)} open ports: {port_list}"
        })

        # Individual risky port checks
        for p in open_ports:
            port_num = p["port"]
            if port_num in RISKY_PORTS:
                risk_detail, severity = RISKY_PORTS[port_num]
                checks.append({
                    "category": "Port Scan",
                    "check": f"Port {port_num} ({p['service']})",
                    "status": "FAIL",
                    "severity": severity,
                    "details": risk_detail
                })
            else:
                checks.append({
                    "category": "Port Scan",
                    "check": f"Port {port_num} ({p['service']})",
                    "status": "PASS",
                    "severity": "Low",
                    "details": f"{p['service']} is open — verify if intended"
                })

        # SSH port check — flag if using default port 22
        ssh_open = any(p["port"] == 22 for p in open_ports)
        if ssh_open:
            checks.append({
                "category": "Port Scan",
                "check": "SSH Default Port",
                "status": "WARNING",
                "severity": "Medium",
                "details": "SSH running on default port 22 — consider using a non-standard port"
            })

        # RDP port check
        rdp_open = any(p["port"] == 3389 for p in open_ports)
        if rdp_open:
            checks.append({
                "category": "Port Scan",
                "check": "RDP Default Port",
                "status": "FAIL",
                "severity": "Critical",
                "details": "RDP on default port 3389 — high brute-force risk, use VPN or change port"
            })

        return checks
