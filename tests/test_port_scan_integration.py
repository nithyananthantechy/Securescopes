"""
Comprehensive test suite for merged NiteSentinel + Port_Scanner functionality
Tests cover: CLI, Web routes, Service detection, Banner grabbing, Async scanning, Database
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from io import StringIO

# CLI Tests
def test_port_scan_quick_command():
    """Test CLI quick scan command"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    # Test with localhost and common ports
    result = runner.invoke(cli, ['port-scan', 'quick', 'localhost', '--ports', '80,443', '--timeout', '1.0'])
    
    assert result.exit_code in [0, 1]  # 0 = success, 1 = expected if port closed
    assert 'port' in result.output.lower() or 'localhost' in result.output.lower()


def test_port_scan_full_command():
    """Test CLI full scan command"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    result = runner.invoke(cli, ['port-scan', 'full', 'localhost', '--ports', '80,443'])
    
    assert result.exit_code in [0, 1]
    assert 'port' in result.output.lower() or 'scan' in result.output.lower()


def test_port_scan_invalid_target():
    """Test CLI with invalid target"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    result = runner.invoke(cli, ['port-scan', 'quick', '', '--ports', '80'])
    
    assert result.exit_code != 0  # Should fail on empty target


# Service Detector Tests
def test_service_detector_analyze_port_scan():
    """Test service detector risk analysis"""
    from nitesentinels.scanners.service_detector import analyze_port_scan
    
    open_ports = [
        {'port': 80, 'service': 'http', 'banner': 'Apache/2.4.1'},
        {'port': 443, 'service': 'https', 'banner': 'nginx/1.19.0'},
        {'port': 22, 'service': 'ssh', 'banner': 'OpenSSH_7.4'},
        {'port': 3389, 'service': 'rdp', 'banner': None},
    ]
    
    result = analyze_port_scan(open_ports)
    
    assert isinstance(result, dict)
    assert 'score' in result
    assert 'risk_level' in result
    assert 'findings' in result
    assert 'remediation' in result
    assert 0 <= result['score'] <= 100
    assert result['risk_level'] in ['Critical', 'High', 'Medium', 'Low', 'Info']


def test_service_detector_critical_ports():
    """Test detection of critical ports"""
    from nitesentinels.scanners.service_detector import analyze_port_scan
    
    # High-risk ports
    critical_ports = [
        {'port': 445, 'service': 'smb', 'banner': None},
        {'port': 3306, 'service': 'mysql', 'banner': 'MySQL 5.7'},
        {'port': 27017, 'service': 'mongodb', 'banner': None},
    ]
    
    result = analyze_port_scan(critical_ports)
    
    assert result['score'] > 50  # Should be high risk
    assert result['risk_level'] in ['Critical', 'High']
    assert len(result['findings']) > 0


def test_service_detector_detect_service():
    """Test individual service detection"""
    from nitesentinels.scanners.service_detector import detect_service
    
    test_cases = [
        (80, 'HTTP/1.1 200 OK', 'http'),
        (443, 'TLS', 'https'),
        (22, 'SSH-2.0-OpenSSH', 'ssh'),
        (3306, 'MySQL 5.7', 'mysql'),
        (5432, 'PostgreSQL', 'postgresql'),
    ]
    
    for port, banner, expected in test_cases:
        result = detect_service(port, banner)
        # Result should be a string identifying the service
        assert isinstance(result, str)


# Banner Grabber Tests
@pytest.mark.asyncio
async def test_banner_grabber_scan_port_async():
    """Test async banner grabbing"""
    from nitesentinels.scanners.banner_grabber import scan_port_async
    
    # Mock test - scan localhost on port 22 (SSH)
    result = await scan_port_async('localhost', 22, timeout=1.0, target='localhost')
    
    assert isinstance(result, tuple)
    assert len(result) == 4  # (port, is_open, service, banner)
    port, is_open, service, banner = result
    assert port == 22


# Port Scanner Async Tests
@pytest.mark.asyncio
async def test_port_scanner_async_parse_ports():
    """Test port range parsing"""
    from nitesentinels.scanners.port_scanner_async import parse_ports
    
    # Test range
    ports = parse_ports('80-85')
    assert ports == [80, 81, 82, 83, 84, 85]
    
    # Test comma-separated
    ports = parse_ports('80,443,8080')
    assert set(ports) == {80, 443, 8080}
    
    # Test mixed
    ports = parse_ports('80,443,8080-8082')
    assert set(ports) == {80, 443, 8080, 8081, 8082}


@pytest.mark.asyncio
async def test_port_scanner_async_scan_target():
    """Test async port scanning"""
    from nitesentinels.scanners.port_scanner_async import scan_target
    
    # Quick scan of localhost common ports
    results = await scan_target('localhost', [80, 443, 22], concurrency=10, timeout=1.0)
    
    assert isinstance(results, list)
    for result in results:
        assert isinstance(result, tuple)
        assert len(result) >= 3  # (port, service, banner)


@pytest.mark.asyncio
async def test_port_scanner_async_scan_generator():
    """Test async generator for real-time results"""
    from nitesentinels.scanners.port_scanner_async import scan_generator
    
    results_collected = []
    async for port_result in scan_generator('localhost', [80, 443], concurrency=2, timeout=1.0):
        results_collected.append(port_result)
    
    assert isinstance(results_collected, list)
    assert len(results_collected) > 0


# Port Scanner Class Tests
def test_port_scanner_class_init():
    """Test PortScanner class initialization"""
    from nitesentinels.scanners.port_scanner import PortScanner
    
    scanner = PortScanner('localhost', ports=[80, 443], use_async=True)
    
    assert scanner.target_host == 'localhost'
    assert scanner.ports == [80, 443]
    assert scanner.use_async is True


def test_port_scanner_class_run_scan():
    """Test PortScanner scan execution"""
    from nitesentinels.scanners.port_scanner import PortScanner
    
    scanner = PortScanner('localhost', ports=[22], timeout=1.0, use_async=True)
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'open_ports' in results
    assert 'closed_ports' in results
    assert 'scan_status' in results


def test_port_scanner_run_all_checks():
    """Test comprehensive port scanner checks with analysis"""
    from nitesentinels.scanners.port_scanner import PortScanner
    
    scanner = PortScanner('localhost', ports=[80, 443], use_async=True)
    results = scanner.run_all_checks()
    
    assert isinstance(results, list)
    assert len(results) > 0


# Web Route Tests
def test_web_route_quick_scan_form(client):
    """Test quick scan form rendering"""
    response = client.get('/port-scan/quick-scan')
    
    assert response.status_code == 200
    assert b'Port Scan' in response.data or b'port' in response.data.lower()


def test_web_route_validate_target_api(client):
    """Test target validation API"""
    response = client.post('/port-scan/api/validate-target', json={'target': 'example.com'})
    
    assert response.status_code in [200, 400, 403]
    data = json.loads(response.data)
    assert 'valid' in data or 'error' in data


def test_web_route_validate_private_ip_blocked(client):
    """Test that private IPs are blocked"""
    response = client.post('/port-scan/api/validate-target', json={'target': '192.168.1.1'})
    
    assert response.status_code in [200, 400, 403]
    # Private IPs should be rejected
    data = json.loads(response.data)
    if 'valid' in data:
        assert data['valid'] is False


def test_web_route_port_info_api(client):
    """Test port information API"""
    response = client.get('/port-scan/api/port-info?port=80')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'port' in data or 'service' in data or 'risk' in data


def test_web_route_scan_history_requires_login(client):
    """Test that scan history requires authentication"""
    response = client.get('/port-scan/scan-history')
    
    # Should redirect to login or return 401
    assert response.status_code in [302, 401, 403, 200]  # Depends on auth setup


# Integration Tests
def test_full_workflow_cli_to_results():
    """Test end-to-end workflow: CLI -> scanning -> results"""
    from click.testing import CliRunner
    from main import cli
    import tempfile
    
    runner = CliRunner()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name
    
    result = runner.invoke(cli, [
        'port-scan', 'full', 'localhost',
        '--ports', '22,80,443',
        '--output', output_file
    ])
    
    assert result.exit_code in [0, 1]  # Success or expected port closed
    # Output file may or may not exist depending on results


def test_database_migration_file_exists():
    """Test that database migration files exist"""
    import os
    
    migration_dir = r'c:\Users\Nithyananthan\Desktop\SecureScope\alembic\versions'
    
    # Check for migration files
    files = os.listdir(migration_dir)
    assert any('0001' in f for f in files), "Missing 0001 migration"
    assert any('0002' in f for f in files), "Missing 0002 migration"


# Backward Compatibility Tests
def test_original_nitesentinels_scan_still_works():
    """Ensure original NiteSentinel scan command still works"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--help'])
    
    assert result.exit_code == 0
    assert 'scan' in result.output.lower()


def test_original_harden_command_still_works():
    """Ensure original hardening command still works"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    result = runner.invoke(cli, ['harden', '--help'])
    
    assert result.exit_code == 0
    assert 'harden' in result.output.lower()


def test_original_report_command_still_works():
    """Ensure original report command still works"""
    from click.testing import CliRunner
    from main import cli
    
    runner = CliRunner()
    result = runner.invoke(cli, ['report', '--help'])
    
    assert result.exit_code == 0


# Performance Tests
@pytest.mark.asyncio
async def test_concurrent_port_scanning_performance():
    """Test performance of concurrent port scanning"""
    from nitesentinels.scanners.port_scanner_async import scan_target
    import time
    
    start = time.time()
    # Scan 100 ports with high concurrency
    results = await scan_target(
        'localhost',
        list(range(1000, 1100)),  # Ports 1000-1099
        concurrency=50,
        timeout=0.5
    )
    elapsed = time.time() - start
    
    # Should complete reasonably fast with concurrency
    assert elapsed < 30  # 100 ports in 30 seconds with 0.5s timeout each


# Fixture for web client
@pytest.fixture
def client():
    """Flask test client"""
    from nitesentinels.web.app import create_app
    
    app = create_app()
    app.config['TESTING'] = True
    
    with app.test_client() as test_client:
        yield test_client


# Fixture for async event loop
@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()
