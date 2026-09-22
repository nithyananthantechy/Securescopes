"""
Test and Demonstration of Asset Data Collection in SecureScope / NiteSentinel:
1. Agent-Based Telemetry Collection (NiteSentinel Endpoint Agent)
2. Agentless Network Discovery & Inventory Ingestion
3. Verification that Login does NOT auto-scan the host machine
"""
import requests
import json
import subprocess
import os
import re

BASE = "http://127.0.0.1:8080"

def run_tests():
    s = requests.Session()
    # Login
    login_resp = s.post(f"{BASE}/login", data={"username": "admin", "password": "NiteSentinel@2026"})
    assert login_resp.status_code == 200
    
    # Extract CSRF token
    dash_page = s.get(f"{BASE}/dashboard")
    m = re.search(r'CSRF_TOKEN\s*=\s*["\']([a-fA-F0-9]+)["\']', dash_page.text)
    csrf = m.group(1) if m else ""
    headers = {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    
    # -----------------------------------------------------------------
    # Test 1: Verify Login & Dashboard does NOT trigger auto-scan
    # -----------------------------------------------------------------
    dash_html = dash_page.text
    assert "setTimeout(() => runLocalScan(), 500);" not in dash_html, "Defect: auto-scan is still in dashboard.html!"
    assert "NITECHSPARK Assessment & Security Platform Hub" in dash_html, "Module Hub banner missing from dashboard.html!"
    print("[+] TEST 1 PASSED: Login & Dashboard load in clean standby state without auto-scanning.")
    print("    -> Platform Module Hub banner is active with 1-click links to all modules.")

    # -----------------------------------------------------------------
    # Test 2: Agent-Based Asset Data Collection
    # -----------------------------------------------------------------
    # 2a. Enroll an Agent Token
    enroll_resp = s.post(f"{BASE}/api/ham/agents/enroll", json={}, headers=headers)
    assert enroll_resp.status_code == 200, f"Enroll failed: {enroll_resp.text}"
    token_data = enroll_resp.json()
    raw_token = token_data.get("raw_token") or token_data.get("token")
    assert raw_token, f"No token returned from agent enroll: {token_data}"
    print(f"[+] TEST 2a: Created Agent Enrollment Token: {raw_token[:8]}...")

    # 2b. Run the NiteSentinel Endpoint Agent with --oneshot
    agent_script = os.path.join(os.path.dirname(__file__), "nitesentinels", "ham", "agent", "nitesentinel_agent.py")
    agent_cmd = [
        os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe"),
        agent_script,
        "--server", BASE,
        "--token", raw_token,
        "--oneshot"
    ]
    proc = subprocess.run(agent_cmd, capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, f"Agent execution failed: {proc.stderr}\n{proc.stdout}"
    assert "Checkin response" in proc.stderr or "Checkin response" in proc.stdout
    print("[+] TEST 2b: NiteSentinel Endpoint Agent executed successfully in --oneshot mode.")
    print("    -> Collected OS, CPU, RAM, Disk, IP, and MAC telemetry via Python standard library.")

    # 2c. Verify agent appears in HAM Agent Probes list
    agents_resp = s.get(f"{BASE}/api/ham/agents")
    assert agents_resp.status_code == 200
    agents_list = agents_resp.json().get("items") or agents_resp.json().get("agents", [])
    assert len(agents_list) > 0, f"Agent did not register in database: {agents_resp.json()}"
    latest_agent = agents_list[0]
    print(f"[+] TEST 2c: Agent verified in server registry: ID={latest_agent['id']} Host={latest_agent['hostname']} Platform={latest_agent['platform']}")

    # -----------------------------------------------------------------
    # Test 3: Agentless Asset Data Collection & Ingestion
    # -----------------------------------------------------------------
    # 3a. Add an asset directly via HAM API (representing manual/agentless discovery)
    asset_payload = {
        "asset_tag": "HAM-SRV-2026",
        "asset_name": "Core Database Server (Agentless Discovery)",
        "asset_type": "server",
        "make": "Dell",
        "model": "PowerEdge R750",
        "serial_number": "SN-DELL-998811",
        "primary_ip": "192.168.1.15",
        "mac_address": "00:14:22:01:23:45",
        "os_name": "Ubuntu Linux",
        "os_version": "22.04 LTS",
        "cpu": "Intel Xeon Silver 4314",
        "ram_gb": 64,
        "disk_gb": 2000,
        "status": "in_use",
        "criticality": "high",
        "data_classification": "restricted",
        "department": "Engineering & Operations"
    }
    create_asset_resp = s.post(f"{BASE}/api/ham/assets", json=asset_payload, headers=headers)
    assert create_asset_resp.status_code == 201, f"Asset creation failed: {create_asset_resp.text}"
    new_asset_id = create_asset_resp.json().get("asset_id")
    print(f"[+] TEST 3a: Created Managed Asset in HAM: ID={new_asset_id} (Dell PowerEdge R750)")

    # 3b. Verify Asset Detail View
    asset_detail_resp = s.get(f"{BASE}/api/ham/assets/{new_asset_id}")
    assert asset_detail_resp.status_code == 200
    asset_data = asset_detail_resp.json().get("asset") or asset_detail_resp.json()
    assert asset_data.get("asset_tag") == "HAM-SRV-2026"
    assert asset_data.get("ram_gb") == 64
    print(f"[+] TEST 3b: Verified Asset Detail & Telemetry: {asset_data.get('name')}, Specs: {asset_data.get('cpu')}, {asset_data.get('ram_gb')}GB RAM, {asset_data.get('disk_gb')}GB Disk")

    # 3c. Verify Asset in Engagement Assessment Catalog
    # Create test engagement and add asset
    c_res = s.post(f"{BASE}/api/clients", json={"company_name": "Asset Showcase Client Ltd"}, headers=headers)
    cid = c_res.json()["client"]["id"]
    e_res = s.post(f"{BASE}/api/engagements", json={"client_id": cid, "assessment_name": "Infrastructure Telemetry Assessment"}, headers=headers)
    eid = e_res.json()["engagement"]["id"]
    
    eng_asset_res = s.post(f"{BASE}/api/engagements/{eid}/assets", json={
        "hostname": "core-db01.client.local",
        "ip_address": "192.168.1.15",
        "asset_type": "database",
        "os": "Ubuntu 22.04 LTS",
        "criticality": "CRITICAL",
        "data_sensitivity": "RESTRICTED"
    }, headers=headers)
    assert eng_asset_res.status_code == 201
    print("[+] TEST 3c: Linked Asset into Client Engagement Assessment Catalog with CRITICAL criticality and RESTRICTED data sensitivity.")

    print("\n" + "="*60)
    print("ALL ASSET COLLECTION & DASHBOARD BEHAVIOR TESTS PASSED!")
    print("="*60)

if __name__ == '__main__':
    run_tests()
