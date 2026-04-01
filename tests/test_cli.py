import pytest
from click.testing import CliRunner
from main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_group_help(runner):
    """CLI group should display help text."""
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'SecureScope' in result.output


def test_cli_scan_command_exists(runner):
    """scan command should be registered."""
    result = runner.invoke(cli, ['scan', '--help'])
    assert result.exit_code == 0
    assert 'Scan' in result.output or 'local' in result.output


def test_cli_report_command_exists(runner):
    """report command should be registered."""
    result = runner.invoke(cli, ['report', '--help'])
    assert result.exit_code == 0
    assert 'report' in result.output.lower() or 'format' in result.output.lower()


def test_cli_harden_command_exists(runner):
    """harden command should be registered."""
    result = runner.invoke(cli, ['harden', '--help'])
    assert result.exit_code == 0
    assert 'harden' in result.output.lower() or 'yes' in result.output.lower()


def test_cli_web_command_exists(runner):
    """web command should be registered."""
    result = runner.invoke(cli, ['web', '--help'])
    assert result.exit_code == 0
    assert 'web' in result.output.lower() or 'port' in result.output.lower()


def test_cli_remote_command_exists(runner):
    """remote command should be registered."""
    result = runner.invoke(cli, ['remote', '--help'])
    assert result.exit_code == 0
    assert 'remote' in result.output.lower() or 'host' in result.output.lower()


def test_cli_invalid_command(runner):
    """Unknown command should fail gracefully."""
    result = runner.invoke(cli, ['nonexistent'])
    assert result.exit_code != 0
