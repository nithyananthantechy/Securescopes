import json
import pytest


def test_ham_dashboard_api(client):
    res = client.get("/api/ham/dashboard")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_assets" in data or "total" in data
    assert "by_type" in data
    assert "by_status" in data or "by_lifecycle" in data


def test_ham_assets_api_crud(client):
    # Create asset via API
    payload = {
        "asset_tag": "API-TEST-001",
        "name": "Integration Test Server",
        "asset_type": "server",
        "manufacturer": "Dell",
        "model": "PowerEdge R760",
        "serial_number": "DEL12345",
        "ip_address": "192.168.1.99",
        "lifecycle_status": "in_service",
        "department": "Engineering"
    }
    create_res = client.post("/api/ham/assets", json=payload)
    assert create_res.status_code in (200, 201)
    create_data = create_res.get_json()
    asset_id = create_data.get("asset_id") or create_data.get("id")
    assert asset_id is not None

    # Get asset details
    get_res = client.get(f"/api/ham/assets/{asset_id}")
    assert get_res.status_code == 200
    asset = get_res.get_json()
    assert asset["name"] == "Integration Test Server"
    assert asset["asset_tag"] == "API-TEST-001"

    # Update asset
    update_res = client.put(f"/api/ham/assets/{asset_id}", json={"location": "Rack 12"})
    assert update_res.status_code == 200

    # Test QR endpoint
    qr_res = client.get(f"/api/ham/assets/{asset_id}/qr")
    assert qr_res.status_code == 200
    assert qr_res.content_type.startswith("image/")

    # Assign asset
    assign_res = client.post(f"/api/ham/assets/{asset_id}/assign", json={
        "assigned_to": "Bob Smith",
        "department": "IT",
        "notes": "Assigned via API test"
    })
    assert assign_res.status_code == 200

    # Lifecycle transition
    life_res = client.post(f"/api/ham/assets/{asset_id}/lifecycle", json={
        "new_status": "in_repair",
        "reason": "Fan failure"
    })
    assert life_res.status_code == 200

    # Delete asset
    del_res = client.delete(f"/api/ham/assets/{asset_id}")
    assert del_res.status_code == 200


def test_ham_warranty_and_reports_api(client):
    # Warranty API
    w_res = client.get("/api/ham/warranty")
    assert w_res.status_code == 200
    w_data = w_res.get_json()
    assert "expired" in w_data or "expired_count" in w_data

    # Report API
    rep_res = client.get("/api/ham/reports/inventory")
    assert rep_res.status_code == 200
    rep_data = rep_res.get_json()
    assert "assets" in rep_data or "total_assets" in rep_data


def test_ham_html_page_routes(client):
    pages = [
        "/ham/",
        "/ham/assets",
        "/ham/discover",
        "/ham/agents",
        "/ham/assignments",
        "/ham/lifecycle",
        "/ham/warranty",
        "/ham/health",
        "/ham/audit",
        "/ham/custody",
        "/ham/retired",
        "/ham/reports",
        "/ham/settings",
    ]
    for page in pages:
        res = client.get(page)
        assert res.status_code in (200, 302), f"Failed route {page}: status {res.status_code}"
