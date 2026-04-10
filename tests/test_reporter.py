import pytest
from securescope.core.reporter import Reporter, get_report_os


def test_report_generate_html_contains_summary():
    results = {
        "checks": [
            {"category": "Test", "check": "One", "status": "PASS", "severity": "Low", "details": "OK"},
            {"category": "Test", "check": "Two", "status": "FAIL", "severity": "Critical", "details": "Bad"}
        ],
        "score": 50,
        "hostname": "test-host",
        "os": "Test OS",
        "ip_address": "1.2.3.4",
        "kernel": "5.4.0"
    }
    reporter = Reporter(org_name="NiTechSpark")
    html = reporter.generate(results, org="NiTechSpark")

    assert "Security Assessment Report" in html
    assert "FAIL" in html
    assert "PASS" in html
    assert "Test" in html
    assert "test-host" in html
    assert "1.2.3.4" in html


def test_generate_html_with_empty_checks():
    """Report should still render with zero checks."""
    results = {"checks": [], "score": 0, "hostname": "host"}
    reporter = Reporter()
    html = reporter.generate(results, org="NiTechSpark")
    assert "NiTechSpark" in html
    assert "0" in html  # score should be 0


def test_generate_html_score_color_green():
    """Score >= 86 should get green color."""
    results = {"checks": [{"category": "T", "check": "C", "status": "PASS", "severity": "Low", "details": "OK"}], "score": 90}
    reporter = Reporter()
    html = reporter.generate(results, org="Test")
    assert "#22c55e" in html  # green color


def test_generate_html_score_color_red():
    """Score < 41 should get red color."""
    results = {"checks": [{"category": "T", "check": "C", "status": "FAIL", "severity": "Critical", "details": "Bad"}], "score": 20}
    reporter = Reporter()
    html = reporter.generate(results, org="Test")
    assert "#ef4444" in html  # red color


def test_generate_html_score_color_blue():
    """Score 71-85 should get blue color."""
    results = {"checks": [], "score": 75}
    reporter = Reporter()
    html = reporter.generate(results, org="Test")
    assert "#3b82f6" in html  # blue color


def test_generate_html_score_color_orange():
    """Score 41-70 should get orange color."""
    results = {"checks": [], "score": 55}
    reporter = Reporter()
    html = reporter.generate(results, org="Test")
    assert "#f97316" in html  # orange color


def test_generate_html_contains_org_name():
    """Generated HTML should mention the org name."""
    results = {"checks": [], "score": 0}
    reporter = Reporter(org_name="TestCorp")
    html = reporter.generate(results, org="TestCorp")
    assert "TestCorp" in html


def test_reporter_default_org():
    """Default org should be NiTechSpark."""
    reporter = Reporter()
    assert reporter.org_name == "NiTechSpark"


def test_get_report_os_returns_string():
    """get_report_os() should return a non-empty string."""
    os_name = get_report_os()
    assert isinstance(os_name, str)
    assert len(os_name) > 0


def test_generate_html_has_table_headers():
    """Report should contain table column headers."""
    results = {
        "checks": [{"category": "Test", "check": "One", "status": "PASS", "severity": "Low", "details": "OK"}],
        "score": 0
    }
    reporter = Reporter()
    html = reporter.generate(results, org="Test")
    # Category is now in h3, others are in th
    assert "Test</h3>" in html
    for header in ["Check", "Status", "Severity", "Details"]:
        assert header in html
