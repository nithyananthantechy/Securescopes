import pytest
from unittest.mock import patch, MagicMock
from securescope.core.scanner import SecureScanner


def test_calculate_stats_empty():
    scanner = SecureScanner()
    stats = scanner.calculate_stats([])
    assert stats == {"score": 0, "passed": 0, "failed": 0, "warnings": 0}


def test_calculate_stats_all_pass():
    scanner = SecureScanner()
    checks = [{"status": "PASS"} for _ in range(10)]
    stats = scanner.calculate_stats(checks)
    assert stats["score"] == 100
    assert stats["passed"] == 10
    assert stats["failed"] == 0
    assert stats["warnings"] == 0


def test_calculate_stats_mixed():
    scanner = SecureScanner()
    checks = [
        {"status": "PASS"},
        {"status": "FAIL"},
        {"status": "WARNING"},
        {"status": "PASS"}
    ]
    stats = scanner.calculate_stats(checks)
    assert stats["score"] == 50
    assert stats["passed"] == 2
    assert stats["failed"] == 1
    assert stats["warnings"] == 1


def test_calculate_stats_all_fail():
    scanner = SecureScanner()
    checks = [{"status": "FAIL"} for _ in range(5)]
    stats = scanner.calculate_stats(checks)
    assert stats["score"] == 0
    assert stats["passed"] == 0
    assert stats["failed"] == 5
    assert stats["warnings"] == 0


def test_calculate_stats_all_warnings():
    scanner = SecureScanner()
    checks = [{"status": "WARNING"} for _ in range(3)]
    stats = scanner.calculate_stats(checks)
    assert stats["score"] == 0
    assert stats["passed"] == 0
    assert stats["failed"] == 0
    assert stats["warnings"] == 3


def test_scan_local_returns_dict_with_expected_keys():
    """scan_local() must return a dict with all required keys."""
    scanner = SecureScanner()
    data = scanner.scan_local()
    assert isinstance(data, dict)
    for key in ("checks", "score", "passed", "failed", "warnings", "platform"):
        assert key in data, f"Missing key: {key}"


def test_scan_local_checks_is_list():
    """The 'checks' value must be a list."""
    scanner = SecureScanner()
    data = scanner.scan_local()
    assert isinstance(data["checks"], list)


def test_scan_local_score_range():
    """Score must be between 0 and 100."""
    scanner = SecureScanner()
    data = scanner.scan_local()
    assert 0 <= data["score"] <= 100


def test_scan_local_each_check_has_required_fields():
    """Each check dict must contain category, check, status, severity, details."""
    scanner = SecureScanner()
    data = scanner.scan_local()
    required_fields = {"category", "check", "status", "severity", "details"}
    for check in data["checks"]:
        assert required_fields.issubset(check.keys()), f"Check missing fields: {check}"


def test_scan_remote_returns_dict_with_expected_keys():
    """scan_remote() must return a dict even when connection fails."""
    scanner = SecureScanner()
    # Use a non-routable address to trigger quick failure
    data = scanner.scan_remote(host="192.0.2.1", user="test", password="test", target_type="linux")
    assert isinstance(data, dict)
    for key in ("checks", "score", "passed", "failed", "warnings"):
        assert key in data, f"Missing key: {key}"


def test_scan_remote_failed_connection_has_fail_check():
    """When connection fails, there should be a FAIL check in results."""
    scanner = SecureScanner()
    data = scanner.scan_remote(host="192.0.2.1", user="test", password="test", target_type="linux")
    fail_checks = [c for c in data["checks"] if c["status"] == "FAIL"]
    assert len(fail_checks) >= 1


def test_calculate_stats_single_pass():
    scanner = SecureScanner()
    stats = scanner.calculate_stats([{"status": "PASS"}])
    assert stats["score"] == 100
    assert stats["passed"] == 1
