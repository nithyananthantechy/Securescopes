import pytest
from nitesentinels.web.app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["user_id"] = "admin"
            sess["csrf_token"] = "test-token"
        yield client

def test_platform_hub_has_logo_and_no_scanner_controls(client):
    res = client.get("/platform")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "nitesentinel_logo.svg" in html
    assert "NITECHSPARK PLATFORM HUB" in html
    assert "Unified Launcher" in html
    # Check module cards exist
    assert "CLIENT ASSESSMENTS" in html
    assert "SECURITY DASHBOARD" in html
    assert "HARDWARE ASSETS" in html
    assert "NETWORK RECON" in html
    assert "REPORTS &amp; AI" in html or "REPORTS & AI" in html
    assert "COMPLIANCE" in html
    assert "ADMINISTRATION" in html
    assert "SYSTEM" in html

def test_client_assessments_contextual_nav_only(client):
    res = client.get("/engagements")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "CLIENT ASSESSMENTS" in html
    assert 'href="/clients"' in html
    assert 'href="/engagements"' in html
    # Must NOT have persistent nav links to other modules in the top nav
    assert 'class="top-nav-item" href="/port-scan' not in html
    assert 'class="top-nav-item" href="/compliance' not in html

def test_security_dashboard_contextual_nav_only(client):
    res = client.get("/security-dashboard")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "SECURITY AUDIT" in html
    assert "Security Overview" in html
    assert "Targets" in html
    assert 'class="top-nav-item" href="/engagements"' not in html
    assert 'class="top-nav-item" href="/ham"' not in html

def test_hardware_assets_contextual_nav_only(client):
    res = client.get("/ham")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "HARDWARE ASSET MANAGEMENT" in html
    assert 'href="/ham/assets"' in html
    assert 'href="/ham/discover"' in html
    assert 'class="top-nav-item" href="/port-scan' not in html
    assert 'class="top-nav-item" href="/compliance' not in html

def test_reports_workspace_dedicated_route(client):
    res = client.get("/reports")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "REPORTS &amp; AI INTELLIGENCE" in html or "REPORTS & AI" in html
    assert "Executive Reports" in html
    assert "Technical Reports" in html

def test_admin_workspace_dedicated_route(client):
    res = client.get("/admin")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "PLATFORM ADMINISTRATION" in html
    assert "User Directory" in html
    assert "Security Audit Trail" in html

def test_system_workspace_dedicated_route(client):
    res = client.get("/system")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "PLATFORM HUB" in html
    assert "SYSTEM &amp; CONFIGURATION" in html or "SYSTEM & CONFIGURATION" in html
    assert "Web Server Engine" in html
    assert "Scheduler Daemon" in html
