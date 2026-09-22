import socket
import concurrent.futures
from nitesentinels.core.utils import logger
from nitesentinels.scanners.port_scanner_async import scan_target
from nitesentinels.scanners.service_detector import (
    analyze_port_scan,
    PORT_RISK_MAP,
)

# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
}

# Risky ports that shouldn't be open (mapped from service_detector.PORT_RISK_MAP)
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
    """
    Port Scanner with async engine upgrade.
    NiteSentinel v1.2 - Integrated CyberScan async port scanning.
    """
    def __init__(self, target_host, ports=None, timeout=1.5, use_async=True):
        # preserve legacy attribute names and new ones
        self.target = target_host
        self.target_host = target_host
        self.ports = ports or list(COMMON_PORTS.keys())
        self.timeout = timeout
        self.use_async = use_async  # Use new async engine by default

    def scan_port(self, port):
        """Legacy synchronous scan for single port. Returns (port, is_open)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return (port, result == 0)
        except Exception:
            return (port, False)

    def run_scan(self):
        """
        Scan all ports and return a structured result dict.
        Uses async engine if available, falls back to threading.
        """
        if self.use_async:
            open_ports = self._run_scan_async()
        else:
            open_ports = self._run_scan_threaded()

        # Build a compatibility dict expected by callers/tests
        closed_ports = [p for p in self.ports if p not in [op['port'] for op in open_ports]]
        return {
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'scan_status': 'completed',
        }

    def _run_scan_async(self):
        """Run scan using CyberScan's high-performance async engine."""
        try:
            port_spec = ",".join(str(p) for p in self.ports)
            results = scan_target(
                self.target,
                ports=port_spec,
                concurrency=100,
                timeout=self.timeout,
                service_probe=True,
                verbose=False
            )
            
            open_ports = []
            for port, service, banner in results:
                open_ports.append({
                    "port": port,
                    "service": service or COMMON_PORTS.get(port, "Unknown"),
                    "banner": banner
                })
            
            return open_ports
        except Exception as e:
            logger.warning(f"Async scan failed, falling back to threaded: {e}")
            return self._run_scan_threaded()

    def _run_scan_threaded(self):
        """Run scan using legacy threaded approach."""
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
        scan_result = self.run_scan()
        open_ports = scan_result.get('open_ports', []) if isinstance(scan_result, dict) else scan_result
        
        if not open_ports:
            checks.append({
                "category": "Port Scan",
                "check": "Open Ports",
                "status": "PASS",
                "severity": "Low",
                "details": f"No common ports open on {self.target}"
            })
            return checks

        # Get risk analysis from service_detector
        port_data = [{"port": p["port"], "service": p.get("service"), "banner": p.get("banner")} for p in open_ports]
        risk_analysis = analyze_port_scan(port_data)
        overall_score = risk_analysis.get("score", 0)
        
        # Summary check
        port_list = ", ".join([f"{p['port']}/{p.get('service', 'Unknown')}" for p in open_ports])
        risk_level = risk_analysis.get("risk_level", "Medium")
        checks.append({
            "category": "Port Scan",
            "check": "Open Ports Summary",
            "status": "FAIL" if overall_score >= 60 else "WARNING" if overall_score >= 30 else "PASS",
            "severity": "Critical" if risk_level == "Critical" else "High" if risk_level == "High" else "Medium" if risk_level == "Medium" else "Low",
            "details": f"{len(open_ports)} open ports (Risk Score: {overall_score}/100): {port_list}"
        })

        # Individual risky port checks
        for p in open_ports:
            port_num = p["port"]
            if port_num in RISKY_PORTS:
                risk_detail, severity = RISKY_PORTS[port_num]
                checks.append({
                    "category": "Port Scan",
                    "check": f"Port {port_num} ({p.get('service', 'Unknown')})",
                    "status": "FAIL",
                    "severity": severity,
                    "details": risk_detail
                })
            else:
                checks.append({
                    "category": "Port Scan",
                    "check": f"Port {port_num} ({p.get('service', 'Unknown')})",
                    "status": "PASS",
                    "severity": "Low",
                    "details": f"{p.get('service', 'Unknown')} is open — verify if intended"
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
