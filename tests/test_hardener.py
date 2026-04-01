import pytest
from unittest.mock import patch, MagicMock
from securescope.core.hardener import SecureHardener


@patch('securescope.core.hardener.detect_platform')
def test_hardener_selects_windows_hardener(mock_platform):
    """On Windows 11, WindowsHardener should be selected."""
    mock_platform.return_value = {"os": "Windows 11", "is_wsl": False, "release": "10", "version": "10.0.22631", "machine": "AMD64"}
    hardener = SecureHardener()
    from securescope.hardeners.windows_hardener import WindowsHardener
    assert isinstance(hardener.hardener, WindowsHardener)


@patch('securescope.core.hardener.detect_platform')
def test_hardener_selects_linux_hardener(mock_platform):
    """On Linux, LinuxHardener should be selected."""
    mock_platform.return_value = {"os": "Linux", "is_wsl": False, "release": "5.15", "version": "#1", "machine": "x86_64"}
    hardener = SecureHardener()
    from securescope.hardeners.linux_hardener import LinuxHardener
    assert isinstance(hardener.hardener, LinuxHardener)


@patch('securescope.core.hardener.detect_platform')
def test_hardener_selects_none_for_unknown(mock_platform):
    """On unknown platform, hardener should be None."""
    mock_platform.return_value = {"os": "FreeBSD", "is_wsl": False, "release": "13", "version": "13.0", "machine": "amd64"}
    hardener = SecureHardener()
    assert hardener.hardener is None


@patch('securescope.core.hardener.detect_platform')
def test_apply_fixes_no_failures(mock_platform):
    """When all checks pass, no fixes should be applied."""
    mock_platform.return_value = {"os": "Windows 11", "is_wsl": False, "release": "10", "version": "10.0.22631", "machine": "AMD64"}
    hardener = SecureHardener(auto_confirm=True)
    checks = [
        {"check": "Guest account disabled", "status": "PASS", "severity": "Critical"},
        {"check": "SMBv1 Disabled", "status": "PASS", "severity": "Critical"},
    ]
    log = hardener.apply_fixes(checks)
    assert log == []


@patch('securescope.core.hardener.detect_platform')
def test_apply_fixes_unknown_check_name(mock_platform):
    """FAIL checks with unknown names should not crash, just skip."""
    mock_platform.return_value = {"os": "Windows 11", "is_wsl": False, "release": "10", "version": "10.0.22631", "machine": "AMD64"}
    hardener = SecureHardener(auto_confirm=True)
    checks = [
        {"check": "Some Unknown Check XYZ", "status": "FAIL", "severity": "Critical"},
    ]
    log = hardener.apply_fixes(checks)
    assert log == []  # no fix function mapped, so nothing applied


@patch('securescope.core.hardener.detect_platform')
def test_apply_fixes_returns_empty_when_no_hardener(mock_platform):
    """On unsupported platform, apply_fixes returns empty list."""
    mock_platform.return_value = {"os": "FreeBSD", "is_wsl": False, "release": "13", "version": "13.0", "machine": "amd64"}
    hardener = SecureHardener(auto_confirm=True)
    checks = [
        {"check": "SMBv1 Disabled", "status": "FAIL", "severity": "Critical"},
    ]
    log = hardener.apply_fixes(checks)
    assert log == []


@patch('securescope.core.hardener.detect_platform')
def test_map_fix_known_windows_checks(mock_platform):
    """map_fix should return callables for known Windows check names."""
    mock_platform.return_value = {"os": "Windows 11", "is_wsl": False, "release": "10", "version": "10.0.22631", "machine": "AMD64"}
    hardener = SecureHardener()
    known_checks = ["SMBv1 Disabled", "Guest account disabled", "Windows Firewall Status"]
    for check_name in known_checks:
        fix = hardener.map_fix(check_name)
        assert fix is not None, f"No fix mapped for: {check_name}"
        assert callable(fix), f"Fix for {check_name} is not callable"


@patch('securescope.core.hardener.detect_platform')
def test_ask_confirmation_returns_true(mock_platform):
    """ask_confirmation should always return True (placeholder behavior)."""
    mock_platform.return_value = {"os": "Windows 11", "is_wsl": False, "release": "10", "version": "10.0.22631", "machine": "AMD64"}
    hardener = SecureHardener()
    assert hardener.ask_confirmation("Any Check") is True
