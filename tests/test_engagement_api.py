import pytest
import json


def test_engagement_routes_render(client):
    """Test web HTML pages render without errors."""
    resp = client.get("/clients")
    assert resp.status_code == 200
    assert b"Client" in resp.data

    resp = client.get("/engagements")
    assert resp.status_code == 200
    assert b"Engagement" in resp.data


def test_client_and_engagement_lifecycle(client):
    """Test full CRUD and assessment lifecycle via API."""
    # 1. Create client
    c_resp = client.post(
        "/api/clients",
        data=json.dumps({
            "name": "Test Client Corp",
            "contact_name": "Alice Smith",
            "contact_email": "alice@testcorp.com",
            "industry": "Finance"
        }),
        content_type="application/json"
    )
    assert c_resp.status_code == 201
    c_data = c_resp.get_json()
    assert "client" in c_data
    client_id = c_data["client"]["id"]
    assert c_data["client"]["company_name"] == "Test Client Corp"

    # 2. List clients
    list_resp = client.get("/api/clients")
    assert list_resp.status_code == 200
    clients = list_resp.get_json()["clients"]
    assert any(c["id"] == client_id for c in clients)

    # 3. Create engagement
    e_resp = client.post(
        "/api/engagements",
        data=json.dumps({
            "client_id": client_id,
            "title": "Q3 Infrastructure Assessment",
            "assessment_type": "comprehensive",
            "lead_assessor": "Security Team"
        }),
        content_type="application/json"
    )
    assert e_resp.status_code == 201
    e_data = e_resp.get_json()
    assert "engagement" in e_data
    eng_id = e_data["engagement"]["id"]

    # 4. Add scope
    s_resp = client.post(
        f"/api/engagements/{eng_id}/scope",
        data=json.dumps({
            "scope_type": "network_cidr",
            "value": "10.0.0.0/24",
            "description": "Internal server network"
        }),
        content_type="application/json"
    )
    assert s_resp.status_code == 201
    s_data = s_resp.get_json()
    assert "scope_id" in s_data

    # 5. Add asset
    a_resp = client.post(
        f"/api/engagements/{eng_id}/assets",
        data=json.dumps({
            "hostname": "srv-app01.local",
            "ip_address": "10.0.0.5",
            "asset_type": "server",
            "criticality": "HIGH",
            "data_sensitivity": "CONFIDENTIAL"
        }),
        content_type="application/json"
    )
    assert a_resp.status_code == 201
    assert "asset_id" in a_resp.get_json()

    # 6. List assessment questions
    q_resp = client.get("/api/questions")
    assert q_resp.status_code == 200
    questions = q_resp.get_json()["questions"]
    assert len(questions) >= 30

    # 7. Record a questionnaire response
    q_id = questions[0]["id"]
    r_resp = client.post(
        f"/api/engagements/{eng_id}/responses/{q_id}",
        data=json.dumps({
            "status": "PASS",
            "notes": "Verified configuration is compliant."
        }),
        content_type="application/json"
    )
    assert r_resp.status_code == 200
    assert r_resp.get_json().get("ok") is True

    # 8. Create a finding
    f_resp = client.post(
        f"/api/engagements/{eng_id}/findings",
        data=json.dumps({
            "title": "Unauthenticated Telnet Service Detected",
            "section": "network",
            "severity": "HIGH",
            "description": "Port 23 is open and transmitting credentials in plaintext.",
            "remediation": "Disable Telnet and use SSH exclusively."
        }),
        content_type="application/json"
    )
    assert f_resp.status_code == 201
    f_data = f_resp.get_json()
    assert f_data["finding"]["severity"] == "HIGH"

    # 9. Fetch executive report preview HTML
    exec_resp = client.get(f"/api/engagements/{eng_id}/reports/executive")
    assert exec_resp.status_code == 200
    assert b"Executive Assessment Report" in exec_resp.data
    assert b"NITECHSPARK" in exec_resp.data

    # 10. Fetch technical report preview HTML
    tech_resp = client.get(f"/api/engagements/{eng_id}/reports/technical")
    assert tech_resp.status_code == 200
    assert b"Technical Assessment Report" in tech_resp.data
    assert b"10.0.0.0/24" in tech_resp.data


def test_all_engagement_pages_render(client):
    """Verify that every engagement view renders HTML with code 200."""
    # 1. Create client & engagement
    c_resp = client.post(
        "/api/clients",
        data=json.dumps({"name": "Full Page Render Test Inc"}),
        content_type="application/json"
    )
    client_id = c_resp.get_json()["client"]["id"]
    e_resp = client.post(
        "/api/engagements",
        data=json.dumps({"client_id": client_id, "title": "Audit Render Check"}),
        content_type="application/json"
    )
    eng_id = e_resp.get_json()["engagement"]["id"]

    pages = [
        f"/clients/{client_id}",
        f"/engagements/{eng_id}",
        f"/engagements/{eng_id}/scope",
        f"/engagements/{eng_id}/assets",
        f"/engagements/{eng_id}/section/iam",
        f"/engagements/{eng_id}/section/backup",
        f"/engagements/{eng_id}/section/network",
        f"/engagements/{eng_id}/section/servers",
        f"/engagements/{eng_id}/section/endpoints",
        f"/engagements/{eng_id}/section/web",
        f"/engagements/{eng_id}/dlp",
        f"/engagements/{eng_id}/findings",
        f"/engagements/{eng_id}/evidence",
        f"/engagements/{eng_id}/risk-register",
        f"/engagements/{eng_id}/remediation",
        f"/engagements/{eng_id}/retest",
        f"/engagements/{eng_id}/reports",
        f"/engagements/{eng_id}/compliance",
    ]

    for p in pages:
        r = client.get(p)
        assert r.status_code == 200, f"Page {p} returned status {r.status_code}"


def test_authenticated_scan_page_render(client):
    """Verify that /port-scan/authenticated-scan renders 200 without TemplateNotFound."""
    resp = client.get("/port-scan/authenticated-scan")
    assert resp.status_code == 200
    assert b"Port Scanner" in resp.data


def test_dynamic_case_insensitive_section_route(client):
    """Verify that uppercase /section/IAM and /section/BACKUP render 200."""
    c_resp = client.post("/api/clients", data=json.dumps({"name": "Case Test"}), content_type="application/json")
    client_id = c_resp.get_json()["client"]["id"]
    e_resp = client.post("/api/engagements", data=json.dumps({"client_id": client_id, "title": "Case Test"}), content_type="application/json")
    eng_id = e_resp.get_json()["engagement"]["id"]

    for sec in ["IAM", "BACKUP", "NETWORK", "SERVERS", "ENDPOINTS", "WEB", "DLP"]:
        resp = client.get(f"/engagements/{eng_id}/section/{sec}")
        assert resp.status_code == 200, f"Uppercase section {sec} failed: {resp.status_code}"


def test_scope_strict_authorization_and_exclusion(client):
    """Test that CIDR authorization and explicit exclusions are strictly evaluated."""
    c_resp = client.post("/api/clients", data=json.dumps({"name": "Scope Test Co"}), content_type="application/json")
    client_id = c_resp.get_json()["client"]["id"]
    e_resp = client.post("/api/engagements", data=json.dumps({"client_id": client_id, "title": "Scope Test"}), content_type="application/json")
    eng_id = e_resp.get_json()["engagement"]["id"]

    # Add 192.168.1.0/24 in-scope, but 192.168.1.50 excluded
    client.post(f"/api/engagements/{eng_id}/scope", data=json.dumps({
        "scope_type": "network_cidr", "value": "192.168.1.0/24"
    }), content_type="application/json")
    client.post(f"/api/engagements/{eng_id}/scope", data=json.dumps({
        "scope_type": "ip_address", "value": "192.168.1.50", "excluded": True
    }), content_type="application/json")

    # In-scope
    v1 = client.post(f"/api/engagements/{eng_id}/scope/validate", data=json.dumps({"target": "192.168.1.20"}), content_type="application/json").get_json()
    assert v1["in_scope"] is True

    # Excluded
    v2 = client.post(f"/api/engagements/{eng_id}/scope/validate", data=json.dumps({"target": "192.168.1.50"}), content_type="application/json").get_json()
    assert v2["in_scope"] is False

    # External
    v3 = client.post(f"/api/engagements/{eng_id}/scope/validate", data=json.dumps({"target": "8.8.8.8"}), content_type="application/json").get_json()
    assert v3["in_scope"] is False


def test_multi_client_data_isolation(client):
    """Verify that Client A and Client B engagements and assets remain completely isolated."""
    cA = client.post("/api/clients", data=json.dumps({"name": "Client Alpha"}), content_type="application/json").get_json()["client"]["id"]
    cB = client.post("/api/clients", data=json.dumps({"name": "Client Beta"}), content_type="application/json").get_json()["client"]["id"]

    eA = client.post("/api/engagements", data=json.dumps({"client_id": cA, "title": "Audit Alpha"}), content_type="application/json").get_json()["engagement"]["id"]
    eB = client.post("/api/engagements", data=json.dumps({"client_id": cB, "title": "Audit Beta"}), content_type="application/json").get_json()["engagement"]["id"]

    # Add asset to A
    client.post(f"/api/engagements/{eA}/assets", data=json.dumps({"hostname": "srv-alpha.local", "asset_type": "server"}), content_type="application/json")

    # Check B has 0 assets
    assetsB = client.get(f"/api/engagements/{eB}/assets").get_json()["assets"]
    assert len(assetsB) == 0

