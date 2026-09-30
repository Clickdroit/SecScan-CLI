"""
SecScan-CLI ?" Web Security Posture & SSL/TLS Audit Scanner
Command-line interface entry point.
"""

import sys
import json
import urllib.request
from urllib.parse import urlparse
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .auditor import audit_ssl, evaluate_headers, compute_audit_summary
from .exporter import export_json, generate_markdown_report

console = Console()

BANNER = r"""
  ____            ____                      ____ _     ___ 
 / ___|  ___  ___/ ___|  ___ __ _ _ __     / ___| |   |_ _|
 \___ \ / _ \/ __\___ \ / __/ _` | '_ \   | |   | |    | | 
  ___) |  __/ (__ ___) | (_| (_| | | | |  | |___| |___ | | 
 |____/ \___|\___|____/ \___\__,_|_| |_|   \____|_____|___|
"""

@click.group()
@click.version_option(version="1.0.0")
def main():
    """SecScan-CLI: Fast Web Security Posture & SSL/TLS Audit Scanner."""
    pass

@main.command()
@click.argument("target_url")
@click.option("--deep", is_flag=True, help="Perform deep scan including sensitive files probe.")
@click.option("--json", "json_output", is_flag=True, help="Output results in JSON format.")
@click.option("--output", "-o", type=click.Path(), help="Export markdown audit report to file.")
def audit(target_url: str, deep: bool, json_output: bool, output: str):
    """Audit the security posture of TARGET_URL."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url

    if not json_output:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print(f"[bold cyan][*] Auditing target:[/bold cyan] [bold yellow]{target_url}[/bold yellow] ({hostname})")

    # Fetch headers
    headers = {}
    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "SecScan-CLI/1.0 (+https://github.com/secscan)"}
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            headers = dict(resp.headers)
    except Exception as e:
        if not json_output:
            console.print(f"[yellow][!] HTTP request note: {e} (proceeding with audit)[/yellow]")

    # Run SSL and header audit
    ssl_result = audit_ssl(hostname, 443 if parsed.scheme == "https" else 80)
    header_results = evaluate_headers(headers)
    summary = compute_audit_summary(target_url, header_results, ssl_result)

    if json_output:
        console.print(json.dumps(summary, indent=2))
        return

    # Render results table
    table = Table(title=f"Security Posture Report ?" {target_url}", border_style="blue")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Points", justify="right")
    table.add_column("Details / Recommendation", style="dim")

    # SSL Row
    ssl_status = f"[bold green]{ssl_result['status']}[/bold green]" if ssl_result['status'] == "PASS" else f"[bold red]{ssl_result['status']}[/bold red]"
    ssl_pts = "+20" if ssl_result['status'] == "PASS" else "+0"
    table.add_row("SSL/TLS Certificate", ssl_status, ssl_pts, ssl_result["recommendation"])

    for item in summary["headers"]:
        status_style = "[bold green]PASS[/bold green]" if item["status"] == "PASS" else "[bold red]FAIL[/bold red]"
        rec = item["value"] if item["status"] == "PASS" else f"[red]{item['recommendation']}[/red]"
        table.add_row(item["category"], status_style, f"+{item['points']}", rec)

    console.print(table)

    # Score panel
    grade_color = "green" if summary["score"] >= 80 else ("yellow" if summary["score"] >= 60 else "red")
    panel_content = (
        f"[bold]Final Security Score:[/bold] [{grade_color}]{summary['score']} / 100[/{grade_color}] "
        f"[bold]Grade:[/bold] [{grade_color}][{summary['grade']}][/{grade_color}]\n"
        f"SSL Issuer: {ssl_result.get('issuer')} | TLS: {ssl_result.get('tls_version')}"
    )
    console.print(Panel(panel_content, border_style=grade_color, expand=False))

    if output:
        md_content = generate_markdown_report(summary)
        with open(output, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"[bold green][?] Saved Markdown report to:[/bold green] {output}")

if __name__ == "__main__":
    main()
