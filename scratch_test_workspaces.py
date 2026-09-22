import requests

BASE_URL = "http://127.0.0.1:8080"
session = requests.Session()

def test_flow():
    print("1. Testing Login...")
    resp = session.post(f"{BASE_URL}/login", data={"username": "admin", "password": "NiteSentinel@2026"}, allow_redirects=False)
    assert resp.status_code in [302, 303], f"Login redirect failed: {resp.status_code}"
    print("   Login redirected to:", resp.headers.get("Location"))
    assert resp.headers.get("Location") == "/platform"

    # Module definitions to verify: (path, module_title, contextual_token, forbidden_tokens)
    modules = [
        (
            "/platform",
            "Platform Hub",
            "NITECHSPARK PLATFORM HUB",
            ["/static/img/nitesentinel_logo.svg"],
            []
        ),
        (
            "/engagements",
            "Client Assessments",
            "CLIENT ASSESSMENT WORKSPACE",
            ["PLATFORM HUB", "/clients", "/engagements"],
            ["top-nav-item\" href=\"/port-scan", "top-nav-item\" href=\"/compliance"]
        ),
        (
            "/security-dashboard",
            "Security Dashboard",
            "SECURITY AUDIT &amp; POSTURE WORKSPACE",
            ["PLATFORM HUB", "Security Overview", "Targets"],
            ["top-nav-item\" href=\"/engagements", "top-nav-item\" href=\"/ham"]
        ),
        (
            "/ham",
            "Hardware Assets",
            "HARDWARE ASSET MANAGEMENT",
            ["PLATFORM HUB", "/ham/assets", "/ham/discover", "/ham/agents"],
            ["top-nav-item\" href=\"/port-scan", "top-nav-item\" href=\"/compliance"]
        ),
        (
            "/port-scan/quick-scan",
            "Network Recon",
            "NETWORK RECONNAISSANCE",
            ["PLATFORM HUB", "Quick Scan", "Port Scanner"],
            ["top-nav-item\" href=\"/engagements", "top-nav-item\" href=\"/ham"]
        ),
        (
            "/compliance",
            "Compliance",
            "COMPLIANCE &amp; FRAMEWORKS",
            ["PLATFORM HUB", "Framework Overview", "NIST CSF 2.0"],
            ["top-nav-item\" href=\"/engagements", "top-nav-item\" href=\"/port-scan"]
        ),
        (
            "/reports",
            "Reports & AI",
            "REPORTS &amp; AI INTELLIGENCE",
            ["PLATFORM HUB", "Reports Overview", "Executive Reports"],
            ["top-nav-item\" href=\"/port-scan", "top-nav-item\" href=\"/compliance"]
        ),
        (
            "/admin",
            "Administration",
            "PLATFORM ADMINISTRATION",
            ["PLATFORM HUB", "Users", "Roles &amp; Permissions"],
            ["top-nav-item\" href=\"/engagements", "top-nav-item\" href=\"/ham"]
        ),
        (
            "/system",
            "System",
            "SYSTEM &amp; CONFIGURATION",
            ["PLATFORM HUB", "Platform Settings", "System Status"],
            ["top-nav-item\" href=\"/engagements", "top-nav-item\" href=\"/ham"]
        ),
    ]

    for path, name, expected_text, required_tokens, forbidden_tokens in modules:
        r = session.get(f"{BASE_URL}{path}")
        assert r.status_code == 200, f"Module {name} ({path}) returned {r.status_code}"
        assert expected_text in r.text, f"Module {name} missing expected text: {expected_text}"
        for tok in required_tokens:
            assert tok in r.text, f"Module {name} missing required token: {tok}"
        for forb in forbidden_tokens:
            assert forb not in r.text, f"Module {name} unexpectedly contains forbidden token: {forb}"
        print(f"   [PASS] {name} ({path}) - Status 200, Contextual Nav & Branding Verified!")

    print("\nALL 9 WORKSPACE ROUTE TESTS PASSED!")

if __name__ == "__main__":
    test_flow()
