import pytest
from unittest.mock import patch


def test_index_route(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'SecureScope' in resp.data


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
        'password': 'SecureScope@2026'
    })
    assert resp.status_code == 302
    assert '/' in resp.headers.get('Location', '')


def test_favicon_route(client):
    """Favicon should return 204 No Content."""
    resp = client.get('/favicon.ico')
    assert resp.status_code == 204


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
    assert b'SecureScope' in resp.data


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
