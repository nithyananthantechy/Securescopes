import pytest
from securescope.core.utils import detect_platform, run_command, get_banner, get_platform_name


def test_detect_platform_returns_expected_keys():
    """detect_platform() must return all required keys."""
    plat = detect_platform()
    assert isinstance(plat, dict)
    for key in ("os", "is_wsl", "release", "version", "machine"):
        assert key in plat, f"Missing key: {key}"


def test_detect_platform_os_not_empty():
    """OS name should not be empty."""
    plat = detect_platform()
    assert len(plat["os"]) > 0


def test_detect_platform_is_wsl_is_bool():
    """is_wsl should be a boolean."""
    plat = detect_platform()
    assert isinstance(plat["is_wsl"], bool)


def test_get_platform_name_returns_string():
    """get_platform_name() should return a non-empty string."""
    name = get_platform_name()
    assert isinstance(name, str)
    assert len(name) > 0


def test_run_command_success():
    """Running a simple command should succeed."""
    result = run_command("echo hello")
    assert result["success"] is True
    assert "hello" in result["stdout"]
    assert result["returncode"] == 0


def test_run_command_failure():
    """Running a non-existent command should fail gracefully."""
    result = run_command("this_command_does_not_exist_xyz_123")
    # Should not raise, should return a result dict
    assert isinstance(result, dict)
    assert "stdout" in result
    assert "stderr" in result


def test_run_command_timeout():
    """Command that exceeds timeout should be handled."""
    # Use a very short timeout with a long-running command
    result = run_command("ping -n 100 127.0.0.1", timeout=1)
    assert result["success"] is False


def test_get_banner_returns_rich_panel():
    """get_banner() should return a Rich Panel object."""
    from rich.panel import Panel
    plat_info = detect_platform()
    banner = get_banner(plat_info)
    assert isinstance(banner, Panel)


def test_run_command_returns_dict_with_all_keys():
    """Result dict should always have stdout, stderr, returncode, success."""
    result = run_command("echo test")
    for key in ("stdout", "stderr", "returncode", "success"):
        assert key in result, f"Missing key: {key}"
