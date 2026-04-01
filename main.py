import click
from rich.console import Console
from rich.table import Table
from securescope.core.utils import detect_platform, get_banner, logger, console
from securescope.core.scanner import SecureScanner
from securescope.core.hardener import SecureHardener
from securescope.core.reporter import SecureReporter
from securescope.offsec.audit import AuditLogger
from securescope.offsec.engine import OffsecEngine
from securescope.offsec.scope_io import load_scope_yaml
import sys
import warnings
warnings.filterwarnings('ignore')

@click.group()
def cli():
    """SecureScope: One Tool. Every Device. Total Visibility."""
    plat_info = detect_platform()
    console.print(get_banner(plat_info))

@cli.command()
@click.argument('target', type=click.Choice(['local']))
def scan(target):
    """Scan the local machine."""
    scanner = SecureScanner()
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
    scanner = SecureScanner()
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
    scanner = SecureScanner()
    data = scanner.scan_local()
    hardener = SecureHardener(auto_confirm=yes)
    log = hardener.apply_fixes(data["checks"])
    
    if not log:
        console.print("[yellow]No critical issues found or no fixes available.[/yellow]")
    else:
        console.print("[green]Hardening process complete.[/green]")

@cli.command()
@click.option('--format', 'fmt', default='pdf', type=click.Choice(['pdf']), help='Report format: pdf')
@click.option('--output', default='securescope_report.pdf', help='Output filename')
@click.option('--org', default='NiTechSpark', help='Organization name')
def report(fmt, output, org):
    """Generate security assessment report"""
    import warnings
    warnings.filterwarnings('ignore')
    console.print("[cyan]Running scan for report...[/cyan]")
    scanner = SecureScanner()
    data = scanner.scan_local()
    
    reporter = SecureReporter(org_name=org)
    plat_info = detect_platform()
    output_file = reporter.generate_pdf(data["checks"], data["score"], plat_info, output_path=output)
    console.print(f"[green]Report saved: {output_file}[/green]")

@cli.command()
@click.option('--port', default=8080, help='Port to run web dashboard')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--demo', is_flag=True, help='Enable live demo mode animations/watermark')
def web(port, host, demo):
    """Start SecureScope web dashboard"""
    import warnings
    warnings.filterwarnings('ignore')
    from securescope.web.app import app
    app.config["DEMO_MODE"] = bool(demo)
    print(f"Starting SecureScope Web Dashboard at http://localhost:{port}")
    app.run(host=host, port=port, debug=False)

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

if __name__ == "__main__":
    cli()
