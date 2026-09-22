import os
import tempfile
import pytest
from nitesentinels.web.ham_store import HAMStore
from nitesentinels.ham.health_engine import evaluate_asset_health
from nitesentinels.ham.risk_engine import compute_asset_risk_score


@pytest.fixture
def temp_ham_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = HAMStore(path)
    store.init_db()
    yield store
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def test_asset_crud(temp_ham_store):
    store = temp_ham_store
    org_id = "test-org-1"

    # Create asset
    asset_data = {
        "asset_tag": "TEST-LAP-001",
        "name": "ThinkPad T14s",
        "asset_type": "laptop",
        "manufacturer": "Lenovo",
        "model": "T14s Gen 3",
        "serial_number": "PF123456",
        "primary_ip": "192.168.1.55",
        "mac_address": "00:11:22:33:44:55",
        "department": "Engineering",
        "lifecycle_status": "deployed",
    }
    asset_id = store.create_asset(org_id=org_id, data=asset_data, created_by="tester")
    assert asset_id is not None

    # Get asset
    asset = store.get_asset(asset_id, org_id)
    assert asset is not None
    assert asset["asset_tag"] == "TEST-LAP-001"
    assert asset["name"] == "ThinkPad T14s"
    assert asset["ip_address"] == "192.168.1.55"

    # Update asset
    ok = store.update_asset(asset_id, org_id, {"location": "Building A, Floor 2"}, updated_by="tester")
    assert ok is True
    updated = store.get_asset(asset_id, org_id)
    assert updated["location"] == "Building A, Floor 2"

    # Soft delete asset
    deleted = store.soft_delete_asset(asset_id, org_id, deleted_by="tester")
    assert deleted is True
    assert store.get_asset(asset_id, org_id) is None


def test_asset_search_and_filter(temp_ham_store):
    store = temp_ham_store
    org_id = "test-org-2"

    store.create_asset(org_id, {"asset_tag": "SRV-01", "name": "Web Server 1", "asset_type": "server", "lifecycle_status": "deployed"}, "admin")
    store.create_asset(org_id, {"asset_tag": "SRV-02", "name": "DB Server 1", "asset_type": "server", "lifecycle_status": "deployed"}, "admin")
    store.create_asset(org_id, {"asset_tag": "LAP-01", "name": "Dev Laptop", "asset_type": "laptop", "lifecycle_status": "spare"}, "admin")

    # Filter by type
    servers = store.list_assets(org_id, asset_type="server")
    assert servers["total"] == 2
    assert len(servers["assets"]) == 2

    # Filter by query
    query_res = store.list_assets(org_id, q="Dev Laptop")
    assert query_res["total"] == 1
    assert query_res["assets"][0]["asset_tag"] == "LAP-01"


def test_asset_assignment_and_custody(temp_ham_store):
    store = temp_ham_store
    org_id = "test-org-3"

    aid = store.create_asset(org_id, {"asset_tag": "LAP-99", "name": "Test Laptop"}, "admin")

    # Assign asset
    store.assign_asset(
        aid, org_id,
        new_assigned_to="Alice Developer",
        assigned_email="alice@example.com",
        new_department="Security",
        new_location="Office 101",
        updated_by="hr-admin",
        notes="Issued on first day"
    )

    asset = store.get_asset(aid, org_id)
    assert asset["assigned_to"] == "Alice Developer"
    assert asset["department"] == "Security"

    # Check custody log
    custody = store.get_custody_log(aid, org_id)
    assert len(custody) >= 1
    assert custody[0]["custodian"] == "Alice Developer"


def test_lifecycle_transitions(temp_ham_store):
    store = temp_ham_store
    org_id = "test-org-4"

    aid = store.create_asset(org_id, {"asset_tag": "RACK-01", "name": "Old Switch", "lifecycle_status": "deployed"}, "admin")

    # Transition to retired
    ok, msg = store.transition_lifecycle(aid, org_id, "retired", updated_by="admin", reason="Reached EOL")
    assert ok is True

    asset = store.get_asset(aid, org_id)
    assert asset["lifecycle_status"] == "retired"

    # History contains record
    history = store.get_asset_history(aid, org_id)
    assert any(h["action"] == "lifecycle_change" for h in history)


def test_agent_enrollment_and_checkin(temp_ham_store):
    store = temp_ham_store
    org_id = "test-org-5"

    token_info = store.create_agent_enrollment_token(org_id, created_by="admin")
    raw_token = token_info["token"]
    assert raw_token is not None

    # Validate token
    validated = store.validate_agent_token(raw_token)
    assert validated is not None
    assert validated["org_id"] == org_id

    # Register agent
    agent_id = store.register_agent(
        org_id=org_id,
        enrollment_token_id=token_info["token_id"],
        hostname="endpoint-workstation",
        platform="Windows 11 (AMD64)",
        version="1.0.0"
    )
    assert agent_id is not None

    # Process check-in telemetry
    telemetry = {
        "hostname": "endpoint-workstation",
        "platform": "Windows 11 (AMD64)",
        "ip_address": "192.168.1.120",
        "cpu": "Intel Core i7",
        "ram": "32 GB",
        "storage": "1 TB",
        "disk_percent": 45.0
    }
    checkin_ok = store.process_agent_checkin(agent_id, telemetry)
    assert checkin_ok is True

    agents = store.list_agents(org_id)
    assert len(agents) == 1
    assert agents[0]["hostname"] == "endpoint-workstation"


def test_health_and_risk_engines():
    asset = {
        "id": "asset-test",
        "lifecycle_status": "in_service",
        "last_agent_checkin": "2026-09-16 12:00:00",
        "cpu_percent": 50,
        "memory_percent": 60,
        "disk_percent": 70,
        "critical_vulns": 0,
        "high_vulns": 1,
    }
    health = evaluate_asset_health(asset)
    assert health["health_status"] in ("healthy", "warning")
    assert 0 <= health["health_score"] <= 100

    risk = compute_asset_risk_score(asset)
    assert risk["risk_level"] in ("low", "medium", "high", "critical")
    assert 0 <= risk["risk_score"] <= 100
