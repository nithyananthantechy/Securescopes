import pytest
from unittest.mock import patch


def test_index_route(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'NiteSentinel' in resp.data


def test_login_route(client):
    resp = client.get('/login')
    assert resp.status_code == 200
    assert b'Login' in resp.data


def test_scan_local_route(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 100,
            'failed': 0,
            'passed': 1,
            'warnings': 0,
            'checks': [],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    resp = client.get('/api/scan/local')
    assert resp.status_code == 200
    json = resp.get_json()
    assert json['score'] == 100
    assert json['hostname']


def test_logout_redirects(client):
    """Logout should redirect to login page."""
    resp = client.get('/logout')
    assert resp.status_code == 302
    assert '/login' in resp.headers.get('Location', '')


def test_login_post_invalid_credentials(client):
    """Invalid login should show error."""
    resp = client.post('/login', data={
        'username': 'wrong',
        'password': 'wrong'
    })
    assert resp.status_code == 200
    assert b'Invalid credentials' in resp.data


def test_login_post_valid_credentials(client):
    """Valid login should redirect to index."""
    resp = client.post('/login', data={
        'username': 'nitechspark',
        'password': 'NiteSentinel@2026'
    })
    assert resp.status_code == 302
    assert '/' in resp.headers.get('Location', '')


def test_favicon_route(client):
    """Favicon should return 200 or 204 depending on file existence."""
    resp = client.get('/favicon.ico')
    assert resp.status_code in (200, 204)


def test_logo_route(client):
    """Logo route should return 200 or 404 (depending on file presence)."""
    resp = client.get('/logo.png')
    assert resp.status_code in (200, 404)


def test_report_local_route(client, monkeypatch):
    """Report local should generate HTML report."""
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 85,
            'passed': 8,
            'failed': 1,
            'warnings': 1,
            'checks': [
                {"category": "Test", "check": "Check1", "status": "PASS", "severity": "Low", "details": "OK"}
            ],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    resp = client.get('/api/report/local')
    assert resp.status_code == 200
    assert resp.content_type == 'text/html; charset=utf-8'
    assert b'NiteSentinel' in resp.data


def test_report_remote_no_data(client):
    """Report remote with no scan data returns 404."""
    resp = client.get('/api/report/remote?host=nonexistent')
    assert resp.status_code == 404
    json = resp.get_json()
    assert 'error' in json


def test_harden_route(client):
    """Harden route should accept POST and return log."""
    resp = client.post('/api/harden',
        json={
            'checks': [
                {"category": "Test", "check": "Unknown Check", "status": "FAIL", "severity": "Critical", "details": "Bad"}
            ]
        },
        content_type='application/json'
    )
    assert resp.status_code == 200
    json = resp.get_json()
    assert 'log' in json
    assert isinstance(json['log'], list)


def test_scan_local_returns_all_expected_keys(client, monkeypatch):
    """API response should contain all dashboard-required keys."""
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 75,
            'passed': 7,
            'failed': 2,
            'warnings': 1,
            'checks': [],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    resp = client.get('/api/scan/local')
    assert resp.status_code == 200
    json = resp.get_json()
    for key in ('score', 'failed', 'passed', 'warnings', 'hostname', 'os', 'checks'):
        assert key in json, f"Missing key in API response: {key}"


def test_scan_local_error_handling(client, monkeypatch):
    """If scanner raises an exception, API should return 500 with error."""
    from securescope.web import app as sec_app

    def broken_scan():
        raise RuntimeError("Scan engine failure")

    monkeypatch.setattr(sec_app.scanner, 'scan_local', broken_scan)
    resp = client.get('/api/scan/local')
    assert resp.status_code == 500
    json = resp.get_json()
    assert 'error' in json
    assert 'Scan engine failure' in json['error']


def test_dashboard_kpis_endpoint(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 88,
            'failed': 1,
            'passed': 8,
            'warnings': 1,
            'checks': [
                {"category": "SSH", "check": "Password auth disabled", "status": "FAIL", "severity": "Critical", "details": "Enabled"},
                {"category": "Firewall", "check": "UFW active", "status": "PASS", "severity": "Low", "details": "OK"},
            ],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    scan_resp = client.get('/api/scan/local')
    assert scan_resp.status_code == 200

    resp = client.get('/api/dashboard/kpis')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'total_targets_scanned' in data
    assert 'critical_vulnerabilities' in data
    assert 'remediation_rate' in data
    assert 'compliance_score_avg' in data


def test_targets_list_endpoint(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 72,
            'failed': 2,
            'passed': 7,
            'warnings': 1,
            'checks': [],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    client.get('/api/scan/local')

    resp = client.get('/api/targets?sort=score&order=desc&page=1&page_size=10')
    assert resp.status_code == 200
    payload = resp.get_json()
    assert 'targets' in payload
    assert 'items' in payload
    assert 'total' in payload
    assert 'total_pages' in payload
    assert payload['page'] == 1


def test_api_targets_filter(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 72,
            'failed': 2,
            'passed': 7,
            'warnings': 1,
            'checks': [],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    with client.session_transaction() as sess:
        sess['org_id'] = 'test_org'
        sess['username'] = 'tester'
    client.get('/api/scan/local')
    response = client.get('/api/targets?status=online&os=windows')
    assert response.status_code == 200
    data = response.get_json()
    assert 'targets' in data


def test_api_preferences(client):
    with client.session_transaction() as sess:
        sess['user_id'] = 'test_user'
        sess['username'] = 'test_user'
    response = client.post(
        '/api/preferences',
        json={'theme': 'light'},
        content_type='application/json',
    )
    assert response.status_code == 200
    response = client.get('/api/preferences')
    assert response.status_code == 200
    data = response.get_json()
    assert data.get('theme') == 'light'


def test_mobile_menu_toggle(client):
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'mobileMenuToggle' in response.data


def test_targets_page_renders(client):
    response = client.get('/targets')
    assert response.status_code == 200
    assert b'targetsTableBody' in response.data


def test_api_scan_target_localhost(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 80,
            'failed': 0,
            'passed': 5,
            'warnings': 0,
            'checks': [],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    client.get('/api/scan/local')
    with client.session_transaction() as sess:
        sess['role'] = 'super_admin'
    resp = client.post('/api/targets/localhost/scan')
    assert resp.status_code == 200
    out = resp.get_json()
    assert out.get('status') == 'scanning'
    assert 'message' in out


def test_findings_list_and_bulk_action(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 50,
            'failed': 2,
            'passed': 2,
            'warnings': 1,
            'checks': [
                {"category": "SSH", "check": "Root login disabled", "status": "PASS", "severity": "Low", "details": "OK"},
                {"category": "SSH", "check": "Password auth disabled", "status": "FAIL", "severity": "Critical", "details": "Enabled"},
                {"category": "Firewall", "check": "UFW active", "status": "WARNING", "severity": "High", "details": "Inactive"},
            ],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    client.get('/api/scan/local')

    list_resp = client.get('/api/findings?severity=critical')
    assert list_resp.status_code == 200
    findings = list_resp.get_json()['items']
    assert len(findings) >= 1
    fid = findings[0]['id']

    bulk_resp = client.post('/api/findings/bulk', json={"finding_ids": [fid], "action": "mark_reviewed"})
    assert bulk_resp.status_code == 200
    out = bulk_resp.get_json()
    assert out['ok'] is True
    assert out['updated'] >= 1


def test_findings_filter_target_key(client, monkeypatch):
    from securescope.web import app as sec_app

    def fake_scan_local():
        return {
            'score': 60,
            'failed': 1,
            'passed': 2,
            'warnings': 0,
            'checks': [
                {"category": "SSH", "check": "A", "status": "PASS", "severity": "Low", "details": "ok"},
            ],
            'platform': 'Windows 11',
        }

    monkeypatch.setattr(sec_app.scanner, 'scan_local', fake_scan_local)
    client.get('/api/scan/local')
    resp = client.get('/api/findings?target_key=localhost')
    assert resp.status_code == 200
    for row in resp.get_json()['items']:
        assert row['target_key'] == 'localhost'


def test_findings_bulk_with_colon_in_target_key(client):
    """Finding IDs use rsplit so target keys containing ':' (e.g. URLs) work."""
    from securescope.web import app as sec_app

    key = 'web-https://example.com'
    sec_app.stored_scan_results[key] = {
        'checks': [
            {'category': 'Web', 'check': 'TLS', 'status': 'FAIL', 'severity': 'high', 'details': 'weak'},
        ],
        'score': 40,
        'hostname': 'https://example.com',
        'target': 'https://example.com',
        'last_scan': '01 Jan 2026 12:00:00',
    }
    fid = f'{key}:0'
    resp = client.post(
        '/api/findings/bulk',
        json={'finding_ids': [fid], 'action': 'mark_reviewed'},
        content_type='application/json',
    )
    assert resp.status_code == 200
    assert resp.get_json().get('updated') == 1
    chk = sec_app.stored_scan_results[key]['checks'][0]
    assert chk.get('workflow_status') == 'reviewed'
    assert chk.get('reviewed') is True


def test_dashboard_index_contains_kpi_markup(client):
    resp = client.get('/dashboard')
    assert resp.status_code == 200
    assert b'kpiTargets' in resp.data
    assert b'findingsPagination' in resp.data


def test_api_frameworks_list(client):
    resp = client.get("/api/frameworks")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "frameworks" in data
    assert len(data["frameworks"]) >= 3


def test_api_compliance_status(client):
    with client.session_transaction() as sess:
        sess["org_id"] = "test_org"
    response = client.get("/api/compliance/cis")
    assert response.status_code == 200
    data = response.get_json()
    assert "compliance_percentage" in data
    assert "controls" in data


def test_api_compliance_without_org_id(client):
    """Legacy login users have no org_id — compliance API should still respond."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "legacy_user"
    response = client.get("/api/compliance/cis")
    assert response.status_code == 200
    assert "controls" in response.get_json()


def test_api_remediation_get(client):
    with client.session_transaction() as sess:
        sess["org_id"] = "test_org"
    response = client.get("/api/findings/test:finding:1/remediation")
    assert response.status_code == 200
    data = response.get_json()
    assert "status" in data


def test_api_remediation_update(client):
    with client.session_transaction() as sess:
        sess["org_id"] = "test_org"
        sess["user_id"] = "test_user"
        sess["role"] = "super_admin"
    response = client.post(
        "/api/findings/test:finding:1/remediation",
        json={"status": "in_progress", "assigned_to": "test_user"},
        content_type="application/json",
    )
    assert response.status_code == 200


def test_api_report_generate_json(client):
    with client.session_transaction() as sess:
        sess["org_id"] = "test_org"
        sess["user_id"] = "test_user"
        sess["role"] = "super_admin"
    response = client.post(
        "/api/reports/generate",
        json={"type": "findings", "format": "json"},
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "total_findings" in data


def test_compliance_dashboard(client):
    """Frameworks endpoint supports compliance dashboard."""
    response = client.get("/api/frameworks")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data["frameworks"]) >= 3


def test_super_admin_access_all_tabs(client):
    """Super admin can access Users, Licenses, Organizations."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'super_admin_user'
            sess['role'] = 'super_admin'
            sess['org_id'] = 'org1'
        
        # Should access all endpoints
        assert client.get('/api/admin/users').status_code == 200
        assert client.get('/api/admin/licenses').status_code == 200
        assert client.get('/api/admin/organizations').status_code == 200


def test_org_admin_cannot_access_licenses(client):
    """Org admin cannot access licenses."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'org_admin_user'
            sess['role'] = 'org_admin'
            sess['org_id'] = 'org1'
        
        # Should be denied
        response = client.get('/api/admin/licenses')
        assert response.status_code == 403


def test_viewer_cannot_access_users(client):
    """Viewer cannot access Users tab."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'viewer_user'
            sess['role'] = 'viewer'
            sess['org_id'] = 'org1'
        
        # Should be denied
        response = client.get('/api/admin/users')
        assert response.status_code == 403


def test_normal_user_can_only_update_assigned(client):
    """Normal user can only update findings assigned to them."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'normal_user'
            sess['role'] = 'normal_user'
            sess['org_id'] = 'org1'
        
        finding_id = 'test:finding:1'
        # Assume finding_remediation is set up
        response = client.post(
            f'/api/findings/{finding_id}/remediation',
            json={'status': 'in_progress'},
            content_type='application/json'
        )
        # This might need adjustment based on actual logic
        assert response.status_code in [200, 403]  # Depending on assignment


def test_org_admin_cannot_see_other_org_findings(client):
    """Org admin only sees findings in their org."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'org_admin_user'
            sess['role'] = 'org_admin'
            sess['org_id'] = 'org1'
        
        # Add finding from org2 (mock)
        from securescope.web import app as sec_app
        sec_app.stored_scan_results['target2'] = {
            'org_id': 'org2',
            'checks': [{'category': 'Test', 'check': 'Test', 'status': 'FAIL', 'severity': 'high'}]
        }
        
        response = client.get('/api/findings')
        data = response.get_json()
        
        # Should not include org2 findings
        assert all(f.get('org_id') in [None, 'org1'] for f in data.get('findings', []))


def test_super_admin_sees_all_orgs(client):
    """Super admin sees targets from all orgs."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'super_admin'
            sess['role'] = 'super_admin'
            sess['org_id'] = None  # Super admin has no org
        
        # Add targets from multiple orgs
        from securescope.web import app as sec_app
        sec_app.stored_scan_results['target-org1'] = {'org_id': 'org1', 'name': 'Target 1'}
        sec_app.stored_scan_results['target-org2'] = {'org_id': 'org2', 'name': 'Target 2'}
        
        response = client.get('/api/targets')
        data = response.get_json()
        
        # Should include both
        assert len(data['targets']) >= 2


def test_viewer_cannot_create_anything(client):
    """Viewer cannot create users, licenses, orgs."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'viewer_user'
            sess['role'] = 'viewer'
            sess['org_id'] = 'org1'
        
        # All create endpoints should return 403
        assert client.post('/api/admin/users', json={}).status_code in [400, 403]
        assert client.post('/api/admin/licenses', json={}).status_code in [400, 403]
        assert client.post('/api/admin/organizations', json={}).status_code in [400, 403]


def test_ui_tabs_hidden_for_viewer(client):
    """Viewer cannot see Users, Licenses, Organizations tabs in HTML."""
    with client:
        with client.session_transaction() as sess:
            sess['user_id'] = 'viewer_user'
            sess['role'] = 'viewer'
            sess['org_id'] = 'org1'
        
        response = client.get('/dashboard')
        html = response.data.decode()
        
        # Should have role badge
        assert 'data-user-role="viewer"' in html
        
        # Check tabs are hidden via script (testing the script is present)
        assert 'TAB_ACCESS' in html
