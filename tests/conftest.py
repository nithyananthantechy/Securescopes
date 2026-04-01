import os
import sys
import pytest

# Ensure the package root is importable during tests
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from securescope.web.app import app as flask_app


@pytest.fixture
def app():
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret"
    })
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_checks_mixed():
    """A reusable set of mixed check results."""
    return [
        {"category": "SSH", "check": "Root login disabled", "status": "PASS", "severity": "Critical", "details": "OK"},
        {"category": "SSH", "check": "Password auth disabled", "status": "FAIL", "severity": "Critical", "details": "Enabled"},
        {"category": "Firewall", "check": "UFW Active", "status": "WARNING", "severity": "High", "details": "Inactive"},
        {"category": "Users", "check": "Only root has UID 0", "status": "PASS", "severity": "High", "details": "OK"},
    ]


@pytest.fixture
def sample_checks_all_pass():
    """All passing checks."""
    return [
        {"category": "Test", "check": f"Check {i}", "status": "PASS", "severity": "Low", "details": "OK"}
        for i in range(5)
    ]


@pytest.fixture
def sample_checks_all_fail():
    """All failing checks."""
    return [
        {"category": "Test", "check": f"Check {i}", "status": "FAIL", "severity": "Critical", "details": "Bad"}
        for i in range(5)
    ]


@pytest.fixture
def sample_scan_result(sample_checks_mixed):
    """A complete scan result dict matching the shape returned by scan_local()."""
    return {
        "checks": sample_checks_mixed,
        "score": 50,
        "passed": 2,
        "failed": 1,
        "warnings": 1,
        "platform": "Windows 11"
    }


@pytest.fixture
def fake_scan_local_fn():
    """Returns a factory that creates a fake scan_local function."""
    def _make(score=80, passed=8, failed=1, warnings=1, checks=None):
        def fake_scan_local():
            return {
                'score': score,
                'passed': passed,
                'failed': failed,
                'warnings': warnings,
                'checks': checks or [
                    {"category": "Test", "check": "Mock Check", "status": "PASS", "severity": "Low", "details": "OK"}
                ],
                'platform': 'Windows 11'
            }
        return fake_scan_local
    return _make
