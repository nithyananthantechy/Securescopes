import pytest
from securescope.core.reporter import SecureReporter, get_report_os


def test_report_generate_html_contains_summary():
    results = {
        "checks": [
            {"category": "Test", "check": "One", "status": "PASS", "severity": "Low", "details": "OK"},
            {"category": "Test", "check": "Two", "status": "FAIL", "severity": "Critical", "details": "Bad"}
        ],
        "score": 50
    }
    reporter = SecureReporter(org_name="NiTechSpark")
    html = reporter.generate(results, org="NiTechSpark")

    assert "SecureScope Report" in html
    assert "FAIL" in html
    assert "PASS" in html
    assert "Critical" in html


def test_generate_html_with_empty_checks():
    """Report should still render with zero checks."""
    results = {"checks": [], "score": 0}
    reporter = SecureReporter()
    html = reporter.generate(results, org="NiTechSpark")
    assert "SecureScope" in html
    assert "0" in html  # score should be 0


def test_generate_html_score_color_green():
    """Score >= 86 should get green color."""
    results = {"checks": [{"category": "T", "check": "C", "status": "PASS", "severity": "Low", "details": "OK"}], "score": 90}
    reporter = SecureReporter()
    html = reporter.generate(results, org="Test")
    assert "#22c55e" in html  # green color


def test_generate_html_score_color_red():
    """Score < 41 should get red color."""
    results = {"checks": [{"category": "T", "check": "C", "status": "FAIL", "severity": "Critical", "details": "Bad"}], "score": 20}
    reporter = SecureReporter()
    html = reporter.generate(results, org="Test")
    assert "#ef4444" in html  # red color


def test_generate_html_score_color_blue():
    """Score 71-85 should get blue color."""
    results = {"checks": [], "score": 75}
    reporter = SecureReporter()
    html = reporter.generate(results, org="Test")
    assert "#3b82f6" in html  # blue color


def test_generate_html_score_color_orange():
    """Score 41-70 should get orange color."""
    results = {"checks": [], "score": 55}
    reporter = SecureReporter()
    html = reporter.generate(results, org="Test")
    assert "#f97316" in html  # orange color


def test_generate_html_contains_org_name():
    """Generated HTML should mention the org name."""
    results = {"checks": [], "score": 0}
    reporter = SecureReporter(org_name="TestCorp")
    html = reporter.generate(results, org="TestCorp")
    assert "TestCorp" in html


def test_reporter_default_org():
    """Default org should be NiTechSpark."""
    reporter = SecureReporter()
    assert reporter.org_name == "NiTechSpark"


def test_get_report_os_returns_string():
    """get_report_os() should return a non-empty string."""
    os_name = get_report_os()
    assert isinstance(os_name, str)
    assert len(os_name) > 0


def test_generate_html_has_table_headers():
    """Report should contain table column headers."""
    results = {"checks": [], "score": 0}
    reporter = SecureReporter()
    html = reporter.generate(results, org="Test")
    for header in ["Category", "Check", "Status", "Severity", "Details"]:
        assert header in html
