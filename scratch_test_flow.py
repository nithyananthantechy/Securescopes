import requests
import sys

BASE = "http://127.0.0.1:8080"
s = requests.Session()

print("--- STEP 1: Verify Login Page ---")
r_login_get = s.get(f"{BASE}/login")
assert r_login_get.status_code == 200, f"Login GET failed: {r_login_get.status_code}"
print("Login page reachable.")

print("--- STEP 2: Authenticate User ---")
r_login_post = s.post(f"{BASE}/login", data={"username": "nitechspark", "password": "NiteSentinel@2026"}, allow_redirects=False)
print(f"Login POST status: {r_login_post.status_code}, Location: {r_login_post.headers.get('Location')}")
assert r_login_post.status_code in (302, 303), f"Expected 302/303 redirect, got {r_login_post.status_code}"
assert r_login_post.headers.get("Location") == "/platform", f"Expected redirect to /platform, got {r_login_post.headers.get('Location')}"
print("SUCCESS: Post-login redirect is strictly /platform (NOT /dashboard)")

print("--- STEP 3: Fetch Platform Hub ---")
r_hub = s.get(f"{BASE}/platform")
assert r_hub.status_code == 200, f"Platform Hub failed: {r_hub.status_code}"
html_hub = r_hub.text

# Check Titles
assert "NITECHSPARK PLATFORM HUB" in html_hub, "Missing title 'NITECHSPARK PLATFORM HUB'"
assert "Unified Cybersecurity Assessment" in html_hub, "Missing subtitle text"
assert "PLATFORM HUB" in html_hub, "Missing breadcrumb text"

# Check NO scanner controls in Hub
assert "btnScan" not in html_hub, "Platform hub must NOT contain btnScan"
assert "findingsList" not in html_hub, "Platform hub must NOT contain findingsList"
print("SUCCESS: Platform Hub has NO scanner controls.")

# Check all 8 modules
expected_modules = [
    ("CLIENT ASSESSMENTS", "OPEN CLIENT ASSESSMENTS", "/engagements"),
    ("SECURITY DASHBOARD", "OPEN SECURITY DASHBOARD", "/security-dashboard"),
    ("HARDWARE ASSET MANAGEMENT", "OPEN HARDWARE ASSETS", "/ham"),
    ("NETWORK & PORT SCANNER", "OPEN NETWORK RECON", "/port-scan/quick-scan"),
    ("REPORTS & AI", "OPEN REPORTS &amp; AI", "/security-dashboard?tab=reports"),
    ("COMPLIANCE", "OPEN COMPLIANCE", "/compliance"),
    ("ADMINISTRATION", "OPEN ADMINISTRATION", "/security-dashboard?tab=users"),
    ("SYSTEM", "OPEN SYSTEM", "/security-dashboard?tab=settings"),
]

for title, btn, route in expected_modules:
    assert title in html_hub, f"Missing module title {title}"
    assert btn in html_hub, f"Missing button {btn}"
    assert route in html_hub, f"Missing route {route}"
    print(f"Verified module: {title} -> {btn} -> {route}")

# Verify compliance disclaimer
assert "Informational alignment only — not certification" in html_hub, "Missing compliance notice"
print("SUCCESS: All 8 modules present with exact titles, buttons, and routes.")

print("--- STEP 4: Test Module Routes ---")
# 1. Security Dashboard
r_sec = s.get(f"{BASE}/security-dashboard")
assert r_sec.status_code == 200, f"/security-dashboard failed: {r_sec.status_code}"
assert "SECURITY DASHBOARD" in r_sec.text
assert "Security Audit Findings" in r_sec.text
assert "PLATFORM HUB" in r_sec.text
print("SUCCESS: /security-dashboard rendered and intact.")

# 2. Client Assessments
r_eng = s.get(f"{BASE}/engagements")
assert r_eng.status_code == 200, f"/engagements failed: {r_eng.status_code}"
assert "CLIENT ASSESSMENTS" in r_eng.text or "Assessment Engagements" in r_eng.text
print("SUCCESS: /engagements rendered and intact.")

# 3. HAM
r_ham = s.get(f"{BASE}/ham")
assert r_ham.status_code == 200, f"/ham failed: {r_ham.status_code}"
assert "HARDWARE ASSETS" in r_ham.text or "Hardware Asset Management" in r_ham.text
print("SUCCESS: /ham rendered and intact.")

# 4. Network Recon
r_recon = s.get(f"{BASE}/port-scan/quick-scan")
assert r_recon.status_code == 200, f"/port-scan/quick-scan failed: {r_recon.status_code}"
assert "Network & Port Scanner" in r_recon.text or "Port Scanner" in r_recon.text
print("SUCCESS: /port-scan/quick-scan rendered and intact.")

# 5. Compliance Module
r_comp = s.get(f"{BASE}/compliance")
assert r_comp.status_code == 200, f"/compliance failed: {r_comp.status_code}"
assert "COMPLIANCE" in r_comp.text
assert "NIST CSF 2.0" in r_comp.text
assert "ISO/IEC 27001" in r_comp.text
assert "CIS Controls" in r_comp.text
assert "PCI DSS" in r_comp.text
assert "DPDP Act 2023" in r_comp.text
assert "Informational Alignment Notice" in r_comp.text
print("SUCCESS: /compliance rendered with all 5 frameworks and disclaimer.")

print("--- STEP 5: Test Agent Token Generation (/api/ham/agents/enroll) ---")
r_agents_page = s.get(f"{BASE}/ham/agents")
import re
csrf_match = re.search(r'const CSRF_TOKEN = "([^"]+)";', r_agents_page.text)
csrf_token = csrf_match.group(1) if csrf_match else ""
r_token = s.post(f"{BASE}/api/ham/agents/enroll", json={"hostname": "test-host", "org_id": "demo-org-1"}, headers={"X-CSRF-Token": csrf_token})
assert r_token.status_code == 200, f"Enrollment token generation failed: {r_token.status_code}, {r_token.text}"
data = r_token.json()
assert "token" in data and "raw_token" in data, f"Token response missing 'token' or 'raw_token': {data}"
assert data.get("ok") is True or data.get("success") is True, f"Token generation not marked success: {data}"
print(f"SUCCESS: Enrollment token successfully generated: token={data['token'][:10]}..., raw_token={data['raw_token'][:10]}...")

print("\nALL VERIFICATION CRITERIA PASSED 100%!")
