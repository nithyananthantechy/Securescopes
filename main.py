import click
from rich.console import Console
from rich.table import Table
from nitesentinels.core.utils import detect_platform, get_banner, logger, console
from nitesentinels.core.scanner import Scanner
from nitesentinels.core.hardener import SecureHardener
from nitesentinels.core.reporter import Reporter
from nitesentinels.offsec.audit import AuditLogger
from nitesentinels.offsec.engine import OffsecEngine
from nitesentinels.offsec.scope_io import load_scope_yaml
import sys
import socket
import platform
import warnings
warnings.filterwarnings('ignore')

@click.group()
def cli():
    """NiteSentinel: One Tool. Every Device. Total Visibility."""
    plat_info = detect_platform()
    console.print(get_banner(plat_info))

@cli.command()
@click.argument('target', type=click.Choice(['local']))
def scan(target):
    """Scan the local machine."""
    scanner = Scanner()
    data = scanner.scan_local()
    checks = data["checks"]
    score = data["score"]
    
    table = Table(title=f"Scan Results (Score: {score}/100)")
    table.add_column("Category", style="cyan")
    table.add_column("Check", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Severity", style="magenta")

    for r in checks:
        status_style = "green" if r["status"] == "PASS" else ("red" if r["status"] == "FAIL" else "yellow")
        table.add_row(r["category"], r["check"], f"[{status_style}]{r['status']}[/]", r["severity"])
    
    console.print(table)
    console.print(f"\n[bold]Overall Security Score: {score}/100[/bold]")

@cli.command()
@click.option('--host', required=True, help='Remote host IP/hostname')
@click.option('--user', required=True, help='SSH username')
@click.option('--password', help='SSH password')
@click.option('--type', 'target_type', default='linux', type=click.Choice(['linux', 'windows', 'network']))
def remote(host, user, password, target_type):
    """Scan a remote target."""
    scanner = Scanner()
    data = scanner.scan_remote(host, user, password=password, target_type=target_type)
    checks = data["checks"]
    score = data["score"]
    
    table = Table(title=f"Remote Scan Results: {host} (Score: {score}/100)")
    table.add_column("Category", style="cyan")
    table.add_column("Check", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Severity", style="magenta")
    
    for r in checks:
        status_style = "green" if r["status"] == "PASS" else ("red" if r["status"] == "FAIL" else "yellow")
        table.add_row(r["category"], r["check"], f"[{status_style}]{r['status']}[/]", r.get("severity", "--"))
    console.print(table)
    console.print(f"\n[bold]Remote Security Score: {score}/100[/bold]")

@cli.command()
@click.option('--yes', is_flag=True, help='Auto-confirm all fixes')
def harden(yes):
    """Harden the local system based on scan results."""
    scanner = Scanner()
    data = scanner.scan_local()
    hardener = SecureHardener(auto_confirm=yes)
    log = hardener.apply_fixes(data["checks"])
    
    if not log:
        console.print("[yellow]No critical issues found or no fixes available.[/yellow]")
    else:
        console.print("[green]Hardening process complete.[/green]")

@cli.command()
@click.option('--format', 'fmt', default='html', type=click.Choice(['html', 'pdf']), help='Report format: html|pdf')
@click.option('--output', default='NiTechSpark_Security_Report.html', help='Output filename')
@click.option('--org', default='NiTechSpark', help='Organization name')
def report(fmt, output, org):
    """Generate security assessment report"""
    import warnings
    warnings.filterwarnings('ignore')
    console.print("[cyan]Running scan for report...[/cyan]")
    scanner = Scanner()
    data = scanner.scan_local()
    
    reporter = Reporter(org_name=org)
    plat_info = detect_platform()
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "127.0.0.1"
        
    report_data = {
        'checks': data['checks'],
        'score': data['score'],
        'hostname': hostname,
        'os': plat_info['os'],
        'kernel': platform.version(),
        'ip_address': ip_address
    }
    
    if fmt == 'html':
        if not output.endswith('.html') and output == 'NiTechSpark_Security_Report.html':
            pass # keep as is
        elif not output.endswith('.html'):
            output += '.html'
            
        html_content = reporter.generate_html(report_data, org=org)
        with open(output, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[green]HTML Report saved: {output}[/green]")
    else:
        output_file = reporter.generate_pdf(data["checks"], data["score"], plat_info, output_path=output)
        console.print(f"[green]PDF Report saved: {output_file}[/green]")

@cli.command()
@click.option('--port', default=8080, help='Port to run web dashboard')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--demo', is_flag=True, help='Enable live demo mode animations/watermark')
def web(port, host, demo):
    """Start NiteSentinel web dashboard"""
    import warnings
    warnings.filterwarnings('ignore')
    from nitesentinels.web.app import app
    app.config["DEMO_MODE"] = bool(demo)
    print(f"Starting NiteSentinel Web Dashboard at http://localhost:{port}")
    app.run(host=host, port=port, debug=False)


@cli.group()
def port_scan():
    """Port scanning and reconnaissance tools (integrated from CyberScan)."""
    pass


@port_scan.command("quick")
@click.argument('target')
@click.option('--ports', default='1-1024', help='Port range/list (e.g., 1-1024, 80,443,8080)')
@click.option('--timeout', default=1.0, type=float, help='Connection timeout in seconds')
@click.option('--concurrency', default=100, type=int, help='Number of concurrent connections')
@click.option('--format', 'fmt', default='text', type=click.Choice(['text', 'json']), help='Output format')
def port_scan_quick(target, ports, timeout, concurrency, fmt):
    """Quick port scan with banner grabbing."""
    import sys
    if not target or not target.strip():
        console.print("[red]Error: Target is required[/red]")
        sys.exit(1)
    from nitesentinels.scanners.port_scanner_async import scan_target
    from nitesentinels.scanners.service_detector import analyze_port_scan
    import json
    
    console.print(f"[cyan]Scanning {target} (ports: {ports})...[/cyan]")
    
    try:
        results = scan_target(
            target,
            ports=ports,
            concurrency=concurrency,
            timeout=timeout,
            service_probe=True,
            verbose=True
        )
        
        if not results:
            console.print("[yellow]No open ports found.[/yellow]")
            return
        
        # Analyze results
        port_data = [{"port": p, "service": s, "banner": b} for p, s, b in results]
        analysis = analyze_port_scan(port_data)
        
        if fmt == 'json':
            output = {
                "target": target,
                "scan": results,
                "analysis": analysis
            }
            console.print(json.dumps(output, indent=2))
        else:
            # Display results in table
            table = Table(title=f"Port Scan Results - {target} (Risk Score: {analysis['score']}/100)")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            table.add_column("Banner", style="white")
            table.add_column("Risk", style="magenta")
            
            for port, service, banner in results:
                banner_short = (banner[:40] + "...") if len(banner) > 40 else banner
                table.add_row(str(port), service, banner_short, analysis["risk_level"])
            
            console.print(table)
            console.print(f"\n[bold]Risk Assessment:[/bold] {analysis['risk_level']} (Score: {analysis['score']}/100)")
            
            if analysis.get("findings"):
                console.print("[bold]Findings:[/bold]")
                for finding in analysis["findings"][:5]:
                    console.print(f"  • [{finding['severity']}] {finding['text']}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Port scan error: {e}")


@port_scan.command("full")
@click.argument('target')
@click.option('--ports', default='1-65535', help='Port range (full scan by default)')
@click.option('--output', help='Save results to JSON file')
def port_scan_full(target, ports, output):
    """Full port scan with detailed analysis."""
    import sys
    if not target or not target.strip():
        console.print("[red]Error: Target is required[/red]")
        sys.exit(1)
    from nitesentinels.scanners.port_scanner_async import scan_target
    from nitesentinels.scanners.service_detector import analyze_port_scan
    import json
    
    console.print(f"[cyan]Running full scan on {target}...[/cyan]")
    
    try:
        results = scan_target(
            target,
            ports=ports,
            concurrency=200,
            timeout=1.0,
            service_probe=True,
            verbose=True
        )
        
        if results:
            port_data = [{"port": p, "service": s, "banner": b} for p, s, b in results]
            analysis = analyze_port_scan(port_data)
            
            output_data = {
                "target": target,
                "open_ports": results,
                "analysis": analysis
            }
            
            if output:
                with open(output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                console.print(f"[green]Results saved to {output}[/green]")
            else:
                console.print(json.dumps(output_data, indent=2))
        else:
            console.print("[yellow]No open ports found.[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Full port scan error: {e}")


@cli.group()
def offsec():
    """Ethical OffSec (scope-gated, safe-by-default)."""
    pass


@offsec.command("scan")
@click.option("--scope-file", required=True, help="Path to scope YAML (required).")
@click.option("--kind", required=True, type=click.Choice(["recon", "web", "api"]), help="Scan kind.")
@click.option("--target", required=True, help="Domain (recon) or URL (web/api).")
@click.option("--actor", default="cli", help="Operator identity for audit trail.")
@click.option("--insecure-tls", is_flag=True, help="Disable TLS certificate verification (NOT recommended).")
def offsec_scan(scope_file, kind, target, actor, insecure_tls):
    """
    Run scope-approved scanning only.

    This will refuse to run if the target is out of scope or the scope file is missing authorization ack.
    """
    scope = load_scope_yaml(scope_file)
    audit = AuditLogger()
    engine = OffsecEngine(scope=scope, audit=audit, actor=actor, safe_mode=True, verify_tls=not insecure_tls)

    res = engine.run(kind, target)

    # Recon returns structured results; web/api returns checks.
    if kind == "recon":
        console.print(f"[bold green]Recon complete[/bold green] run_id={res['run_id']} target={res['target']}")
        subdomains = res["results"]["subdomains"]
        if subdomains:
            t = Table(title="Subdomains (A records)")
            t.add_column("Host", style="cyan")
            t.add_column("A", style="white")
            for s in subdomains:
                t.add_row(s.get("host", ""), str(s.get("a", "")))
            console.print(t)
        else:
            console.print("[yellow]No subdomains found with safe wordlist.[/yellow]")
        return

    checks = res.get("checks") or []
    score = int((sum(1 for c in checks if c.get("status") == "PASS") / max(1, len(checks))) * 100)
    table = Table(title=f"OffSec {kind.upper()} Results (Score: {score}/100)")
    table.add_column("Category", style="cyan")
    table.add_column("Check", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Severity", style="magenta")

    for r in checks:
        status = r.get("status", "--")
        status_style = "green" if status == "PASS" else ("red" if status == "FAIL" else "yellow")
        table.add_row(r.get("category", "--"), r.get("check", "--"), f"[{status_style}]{status}[/]", r.get("severity", "--"))

    console.print(table)
    console.print(f"\n[bold]Run ID:[/bold] {res.get('run_id')}  [bold]Target:[/bold] {res.get('target')}")


# ===========================================================================
# HAM — Hardware Asset Management CLI
# ===========================================================================

@cli.group()
def ham():
    """Hardware Asset Management (HAM) tools and inventory."""
    pass


@ham.command("list")
@click.option("--type", "asset_type", default=None, help="Filter by asset type (laptop, server, switch, etc.)")
@click.option("--status", "lifecycle_status", default=None, help="Filter by lifecycle status (in_service, in_stock, etc.)")
@click.option("--limit", default=25, type=int, help="Maximum number of assets to display")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format")
def ham_list(asset_type, lifecycle_status, limit, fmt):
    """List hardware assets in inventory."""
    import json
    from nitesentinels.web.app import ham_store

    res = ham_store.list_assets(org_id=None, asset_type=asset_type, lifecycle_status=lifecycle_status, page_size=limit)
    assets = res.get("assets", [])

    if fmt == "json":
        click.echo(json.dumps(assets, indent=2))
        return

    table = Table(title=f"Hardware Asset Inventory ({len(assets)} shown, {res.get('total', 0)} total)")
    table.add_column("Asset Tag", style="cyan", no_wrap=True)
    table.add_column("Name / Model", style="white")
    table.add_column("Type", style="magenta")
    table.add_column("Serial #", style="dim")
    table.add_column("IP Address", style="yellow")
    table.add_column("Custodian", style="green")
    table.add_column("Status", style="bold")
    table.add_column("Health", style="blue")
    table.add_column("Risk", style="red")

    for a in assets:
        table.add_row(
            a.get("asset_tag") or a.get("id", "")[:8],
            f"{a.get('name', '—')} ({a.get('manufacturer', '')})",
            a.get("asset_type") or "other",
            a.get("serial_number") or "—",
            a.get("ip_address") or "—",
            a.get("assigned_to") or "Unassigned",
            a.get("lifecycle_status") or "in_stock",
            a.get("health_status") or "unknown",
            f"{a.get('risk_level', 'low')} ({int(a.get('risk_score', 0))})"
        )

    console.print(table)


@ham.command("get")
@click.argument("asset_id")
def ham_get(asset_id):
    """Get detailed specification for a hardware asset."""
    from nitesentinels.web.app import ham_store

    asset = ham_store.get_asset(asset_id)
    if not asset:
        console.print(f"[red]Asset not found: {asset_id}[/red]")
        return

    table = Table(title=f"Asset Details: {asset.get('asset_tag')} — {asset.get('name')}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for k, v in sorted(asset.items()):
        if v is not None and v != "":
            table.add_row(k, str(v))

    console.print(table)


@ham.command("add")
@click.option("--tag", required=True, help="Asset Tag / Barcode identifier (e.g. NS-HW-0042)")
@click.option("--name", required=True, help="Asset Name (e.g. Dell PowerEdge R760)")
@click.option("--type", "asset_type", default="laptop", help="Asset Type (laptop, server, switch, etc.)")
@click.option("--mfg", default="", help="Manufacturer (e.g. Dell, Cisco, Apple)")
@click.option("--model", default="", help="Hardware model")
@click.option("--serial", default="", help="Serial number")
@click.option("--ip", default="", help="IP address")
@click.option("--status", default="in_stock", help="Lifecycle status")
@click.option("--dept", default="", help="Department")
def ham_add(tag, name, asset_type, mfg, model, serial, ip, status, dept):
    """Add a new hardware asset to inventory."""
    from nitesentinels.web.app import ham_store

    payload = {
        "asset_tag": tag,
        "name": name,
        "asset_type": asset_type,
        "manufacturer": mfg,
        "model": model,
        "serial_number": serial,
        "ip_address": ip,
        "lifecycle_status": status,
        "department": dept
    }

    try:
        new_id = ham_store.create_asset(org_id="demo-org-1", data=payload, created_by="cli-user")
        console.print(f"[bold green]Asset created successfully![/bold green] ID: {new_id} Tag: {tag}")
    except Exception as e:
        console.print(f"[bold red]Failed to create asset:[/bold red] {e}")


@ham.command("discover")
@click.argument("subnet")
def ham_discover(subnet):
    """Agentless discovery sweep for a target subnet (e.g. 192.168.1.0/24)."""
    from nitesentinels.web.app import ham_store

    console.print(f"[cyan]Initiating agentless discovery on {subnet}...[/cyan]")
    job_id = ham_store.create_discovery_job(org_id="demo-org-1", subnet=subnet, created_by="cli-operator")
    console.print(f"[green]Discovery job queued![/green] Job ID: {job_id}")


@ham.command("report")
def ham_report():
    """Display executive HAM inventory & risk summary."""
    from nitesentinels.web.app import ham_store

    kpis = ham_store.get_dashboard_kpis(org_id=None)
    table = Table(title="Hardware Asset Management — Executive Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold green")

    table.add_row("Total Assets", str(kpis.get("total_assets", 0)))
    table.add_row("Active in Service", str(kpis.get("active_assets", 0)))
    table.add_row("In Stock / Reserve", str(kpis.get("in_stock", 0)))
    table.add_row("High / Critical Risk", str(kpis.get("high_risk", 0) + kpis.get("critical_risk", 0)))
    table.add_row("Unhealthy State", str(kpis.get("unhealthy_assets", 0)))
    table.add_row("Expiring Warranty (90d)", str(kpis.get("warranty_expiring_soon", 0)))
    table.add_row("Active Agents", f"{kpis.get('agents_online', 0)} / {kpis.get('agents_total', 0)}")

    console.print(table)


if __name__ == "__main__":
    cli()
