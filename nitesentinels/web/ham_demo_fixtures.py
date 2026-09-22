"""
NiteSentinel Hardware Asset Management — Demo Fixtures
======================================================
Provides 75 realistic enterprise hardware assets across workstations,
servers, core network appliances, storage arrays, and IoT equipment.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from nitesentinels.web.ham_store import HAMStore


DEMO_ASSET_TEMPLATES = [
    # 25 Laptops
    ("laptop", "ThinkPad X1 Carbon Gen 11", "Lenovo", "Intel Core i7-1365U", "32 GB", "1 TB NVMe", "Windows 11 Pro", 1850.0),
    ("laptop", "MacBook Pro 16 M3 Max", "Apple", "Apple M3 Max (16-core)", "64 GB", "2 TB SSD", "macOS Sonoma 14.5", 3499.0),
    ("laptop", "MacBook Pro 14 M3 Pro", "Apple", "Apple M3 Pro (12-core)", "36 GB", "1 TB SSD", "macOS Sonoma 14.5", 2399.0),
    ("laptop", "Dell Latitude 5540", "Dell", "Intel Core i5-1345U", "16 GB", "512 GB SSD", "Windows 11 Pro", 1240.0),
    ("laptop", "HP EliteBook 840 G10", "HP", "Intel Core i7-1360P", "32 GB", "1 TB SSD", "Windows 11 Pro", 1680.0),
    ("laptop", "Dell XPS 15 9530", "Dell", "Intel Core i7-13700H", "32 GB", "1 TB NVMe", "Ubuntu 22.04 LTS", 2150.0),
    ("laptop", "Framework Laptop 16", "Framework", "AMD Ryzen 7 7840HS", "32 GB", "1 TB NVMe", "Fedora 39", 1799.0),
    ("laptop", "Lenovo ThinkPad P16 Gen 2", "Lenovo", "Intel Core i9-13900HX", "64 GB", "2 TB NVMe", "Windows 11 Pro", 3890.0),

    # 15 Desktops / Workstations
    ("desktop", "Dell Precision 3660 Workstation", "Dell", "Intel Core i9-13900", "64 GB", "2 TB NVMe", "Windows 11 Pro", 2780.0),
    ("desktop", "HP Z4 G5 Workstation", "HP", "Intel Xeon w5-2455X", "128 GB", "4 TB NVMe", "Red Hat Enterprise Linux 9", 5400.0),
    ("desktop", "Apple Mac Studio M2 Ultra", "Apple", "Apple M2 Ultra (24-core)", "128 GB", "2 TB SSD", "macOS Sonoma", 3999.0),
    ("desktop", "Lenovo ThinkCentre M90q Tiny", "Lenovo", "Intel Core i5-13500T", "16 GB", "512 GB SSD", "Windows 11 Pro", 980.0),

    # 15 Enterprise Rack Servers
    ("server", "PowerEdge R760 Rack Server", "Dell", "Dual Intel Xeon Platinum 8480+", "512 GB DDR5", "8x 3.84TB NVMe SSD", "VMware ESXi 8.0", 18500.0),
    ("server", "PowerEdge R660 1U Server", "Dell", "Dual Intel Xeon Gold 6448Y", "256 GB DDR5", "4x 1.92TB NVMe SSD", "Ubuntu 22.04 LTS", 12400.0),
    ("server", "ProLiant DL380 Gen11", "HPE", "Dual Intel Xeon Gold 5418Y", "256 GB DDR5", "8x 2.4TB SAS 10K", "Red Hat Enterprise Linux 9", 14200.0),
    ("server", "Cisco UCS C240 M7", "Cisco", "Dual Intel Xeon Platinum 8468", "512 GB DDR5", "12x 1.92TB SATA SSD", "VMware ESXi 8.0", 21000.0),
    ("server", "Supermicro SuperServer 2U", "Supermicro", "Dual AMD EPYC 9654 (96-core)", "768 GB DDR5", "16x 7.68TB NVMe", "Proxmox VE 8.1", 24500.0),

    # 10 Network Core & Edge Appliances
    ("switch", "Catalyst 9300 48-Port PoE+", "Cisco", "Cisco x86 ASIC", "16 GB", "16 GB Flash", "Cisco IOS-XE 17.9", 6800.0),
    ("switch", "Arista 7050SX3 48-Port 10G/100G", "Arista", "Broadcom Trident 3", "32 GB", "64 GB SSD", "Arista EOS 4.30", 14500.0),
    ("firewall", "FortiGate 200F Next-Gen Firewall", "Fortinet", "FortiASIC CP9/NP6XLite", "8 GB", "32 GB SSD", "FortiOS 7.4.2", 8900.0),
    ("firewall", "Palo Alto PA-3410 Next-Gen FW", "Palo Alto Networks", "Dedicated Multicore ASIC", "16 GB", "120 GB SSD", "PAN-OS 11.0", 16800.0),
    ("router", "Cisco ASR 1001-X Router", "Cisco", "Dual Core QuantumFlow Processor", "16 GB", "8 GB Flash", "Cisco IOS-XE 17.6", 9800.0),

    # 10 Storage, Printer & IoT Devices
    ("storage", "FlashStation FS6400 All-Flash SAN", "Synology", "Dual Intel Xeon Silver 4110", "64 GB DDR4", "24x 3.84TB SAS SSD", "Synology DSM 7.2", 15200.0),
    ("storage", "PowerVault ME5024 Storage Array", "Dell", "Dual Controller Active/Active", "32 GB Cache", "24x 1.92TB SSD", "Dell Storage OS", 19800.0),
    ("printer", "HP LaserJet Enterprise MFP M635", "HP", "HP Embedded Controller", "2 GB", "500 GB Secure HDD", "HP FutureSmart 5", 2800.0),
    ("iot", "Smart Environmental Sensor Hub", "Bosch", "ARM Cortex-M4", "512 KB", "2 MB Flash", "FreeRTOS 10.4", 320.0),
    ("iot", "Axis Q3538-LVE 4K Security Camera", "Axis Communications", "ARTPEC-8 SoC", "2 GB", "128 GB MicroSD", "Axis OS 11.8", 1250.0),
]

DEPARTMENTS = ["Engineering", "Security Operations", "Infrastructure", "Finance", "Human Resources", "Executive", "Customer Success", "Data Platform"]
LOCATIONS = ["HQ - Datacenter Room A", "HQ - Floor 2 East", "HQ - Floor 3 West", "HQ - Executive Suite", "London Branch Office", "Singapore Regional Hub", "Austin Lab Site"]
STAFF = [
    ("Nithyananthan K", "nithyananthan@nitechspark.com", "Engineering"),
    ("Elena Vance", "elena.vance@nitechspark.com", "Security Operations"),
    ("Marcus Chen", "marcus.chen@nitechspark.com", "Infrastructure"),
    ("Sarah Jenkins", "s.jenkins@nitechspark.com", "Finance"),
    ("David Okafor", "d.okafor@nitechspark.com", "Data Platform"),
    ("Ananya Sharma", "ananya.s@nitechspark.com", "Engineering"),
    ("Robert Taylor", "robert.t@nitechspark.com", "Human Resources"),
    ("Victoria Sterling", "v.sterling@nitechspark.com", "Executive"),
]


def generate_75_demo_assets(org_id: str = "demo-org-1") -> list[dict[str, Any]]:
    """Generate exactly 75 rich, realistic hardware assets for demonstration."""
    assets = []
    base_date = datetime(2023, 1, 15)

    for i in range(1, 76):
        tmpl = DEMO_ASSET_TEMPLATES[(i - 1) % len(DEMO_ASSET_TEMPLATES)]
        asset_type, model_name, mfg, cpu, ram, storage, os_name, cost = tmpl

        type_abbr = asset_type[:3].upper()
        asset_tag = f"NS-{type_abbr}-{i:04d}"
        name = f"{mfg} {model_name} #{i:02d}"

        # Assign custodian for workstations, or datacenter for servers/switches
        if asset_type in ("laptop", "desktop"):
            staff_member = STAFF[(i - 1) % len(STAFF)]
            assigned_to = staff_member[0]
            assigned_email = staff_member[1]
            department = staff_member[2]
            location = random.choice([l for l in LOCATIONS if "Floor" in l or "Office" in l])
            status = "in_service" if i <= 35 else ("in_stock" if i <= 40 else "in_repair")
        else:
            assigned_to = "Infrastructure Team"
            assigned_email = "infra-ops@nitechspark.com"
            department = "Infrastructure"
            location = random.choice([l for l in LOCATIONS if "Datacenter" in l or "Lab" in l])
            status = "in_service" if i <= 65 else ("retired" if i <= 72 else "pending_disposal")

        # Purchase and warranty dates
        p_offset = random.randint(100, 1000)
        p_date = base_date + timedelta(days=p_offset)
        w_exp = p_date + timedelta(days=random.choice([365, 730, 1095]))  # 1, 2, or 3 yr warranty

        # Health & risk
        if i % 12 == 0:
            health_status = "critical"
            health_score = random.randint(20, 45)
            risk_level = "critical"
            risk_score = random.randint(85, 98)
        elif i % 5 == 0:
            health_status = "warning"
            health_score = random.randint(55, 75)
            risk_level = "high"
            risk_score = random.randint(65, 84)
        else:
            health_status = "healthy"
            health_score = random.randint(88, 100)
            risk_level = "low" if i % 2 == 0 else "medium"
            risk_score = random.randint(10, 45)

        # Network IP & MAC
        ip = f"192.168.1.{10 + (i % 230)}"
        mac = f"02:00:5e:{(i // 256):02x}:{(i % 256):02x}:{(i * 3 % 256):02x}"
        serial = f"{mfg[:3].upper()}{random.randint(100000, 999999)}"

        assets.append({
            "asset_tag": asset_tag,
            "name": name,
            "asset_type": asset_type,
            "manufacturer": mfg,
            "model": model_name,
            "serial_number": serial,
            "operating_system": os_name,
            "os_version": "Latest Stable",
            "cpu": cpu,
            "ram": ram,
            "storage": storage,
            "ip_address": ip,
            "mac_address": mac,
            "subnet": "192.168.1.0/24",
            "hostname": f"{type_abbr.lower()}-{i:03d}.corp.local",
            "location": location,
            "rack_position": f"Rack R-0{(i % 6) + 1}, U{(i % 38) + 1}" if asset_type in ("server", "switch", "firewall", "storage") else None,
            "department": department,
            "assigned_to": assigned_to,
            "assigned_email": assigned_email,
            "assignment_date": (p_date + timedelta(days=10)).strftime("%Y-%m-%d"),
            "lifecycle_status": status,
            "purchase_date": p_date.strftime("%Y-%m-%d"),
            "purchase_cost": cost,
            "warranty_expiration": w_exp.strftime("%Y-%m-%d"),
            "vendor": f"{mfg} Direct Enterprise",
            "support_contract": f"SUP-{mfg[:3].upper()}-{random.randint(10000, 99999)}",
            "end_of_life": (p_date + timedelta(days=1825)).strftime("%Y-%m-%d"),  # 5 yr EOL
            "health_status": health_status,
            "health_score": health_score,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "cpu_percent": random.randint(12, 88),
            "memory_percent": random.randint(25, 92),
            "disk_percent": random.randint(20, 85),
            "last_checkin": (datetime.utcnow() - timedelta(minutes=random.randint(5, 720))).strftime("%Y-%m-%d %H:%M:%S"),
            "notes": f"NiteSentinel demonstration hardware asset #{i}."
        })

    return assets


def seed_ham_demo_data(store: HAMStore, org_id: str = "demo-org-1") -> int:
    """Seed the 75 demo assets if none exist for the org."""
    existing = store.list_assets(org_id=org_id, page_size=5)
    if existing.get("total", 0) >= 70:
        return 0

    assets = generate_75_demo_assets(org_id=org_id)
    count = 0
    for a in assets:
        try:
            store.create_asset(org_id=org_id, data=a, created_by="system-seed")
            count += 1
        except Exception:
            pass

    return count
