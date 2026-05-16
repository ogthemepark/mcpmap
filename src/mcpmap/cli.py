from __future__ import annotations
import asyncio
import json
from pathlib import Path
import typer
from rich import print as rprint
from rich.table import Table
from mcpmap import __version__
from mcpmap.pipeline import run_scan, enrich_target, all_checks
from mcpmap.discover.active import active_discover, PRIORITY_PORTS
from mcpmap.discover.shodan_source import shodan_targets
from mcpmap.discover.configs import discover_configs
from mcpmap.audit.runner import run_checks
from mcpmap.report.json_out import to_json
from mcpmap.report.markdown_out import to_markdown
from mcpmap.report.html_out import to_html
from mcpmap.report.poc_out import render_poc
from mcpmap.models import Target, ScanResult


app = typer.Typer(name="mcpmap", help="Nmap for MCP servers — discover, fingerprint, audit.", no_args_is_help=True)


def _version_cb(value: bool):
    if value:
        rprint(f"mcpmap [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.callback()
def main(version: bool = typer.Option(None, "--version", callback=_version_cb, is_eager=True)):
    """mcpmap — Model Context Protocol vulnerability scanner."""


@app.command()
def discover(target: str, shodan: bool = typer.Option(False, "--shodan")):
    """Find MCP servers (active scan, Shodan, or local config)."""
    if shodan:
        ts = shodan_targets(queries=[target])
    else:
        ts = asyncio.run(active_discover(target, ports=PRIORITY_PORTS))
    table = Table("host", "port", "path", "source")
    for t in ts:
        table.add_row(t.host, str(t.port), t.path_hint or "-", t.source)
    rprint(table)


@app.command()
def fingerprint(url: str):
    """Identify framework, version, capabilities for one MCP URL."""
    from urllib.parse import urlparse
    u = urlparse(url)
    t = Target(host=u.hostname, port=u.port or 80, path_hint=u.path, source="url")
    s = asyncio.run(enrich_target(t))
    if not s:
        rprint("[red]not an MCP server[/red]")
        raise typer.Exit(1)
    rprint(f"[green]{s.fingerprint_id or 'unknown'}[/green] — {s.server_info.name} {s.server_info.version}")
    rprint(f"transport: {s.transport}, tools: {len(s.tools)}")


@app.command()
def audit(
    url: str,
    passive: bool = typer.Option(False, "--passive"),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                  help="Show evidence, repro, and remediation per finding."),
):
    """Run vulnerability checks against one MCP URL."""
    import concurrent.futures
    from urllib.parse import urlparse

    def _run(coro):
        """Run a coroutine. If a loop is already running (e.g. inside pytest-asyncio),
        spin up a fresh loop in a background thread to avoid blocking the test loop."""
        try:
            asyncio.get_running_loop()
            running = True
        except RuntimeError:
            running = False
        if running:
            result_holder: list = []
            exc_holder: list = []

            def _thread_target():
                try:
                    result_holder.append(asyncio.run(coro))
                except BaseException as exc:  # noqa: BLE001
                    exc_holder.append(exc)

            import threading
            t = threading.Thread(target=_thread_target, daemon=True)
            t.start()
            t.join()
            if exc_holder:
                raise exc_holder[0]
            return result_holder[0]
        return asyncio.run(coro)

    u = urlparse(url)
    t = Target(host=u.hostname, port=u.port or 80, path_hint=u.path, source="url")
    s = _run(enrich_target(t))
    if not s:
        rprint("[red]not an MCP server[/red]")
        raise typer.Exit(1)
    fs = _run(run_checks(s, all_checks(), passive=passive))
    table = Table("check", "severity", "cvss", "title")
    for f in fs:
        table.add_row(f.check, f.severity.value, str(f.cvss or "-"), f.title)
    rprint(table)
    if verbose:
        from mcpmap.audit.remediations import lookup as _rem_lookup
        for f in fs:
            rprint(f"\n[bold cyan]── {f.check} ──[/bold cyan]")
            ev_data = f.evidence.model_dump(exclude_none=True) if hasattr(f.evidence, "model_dump") else (f.evidence or {})
            if ev_data:
                rprint("[dim]Evidence:[/dim]")
                rprint(json.dumps(ev_data, indent=2))
            if f.repro:
                rprint(f"[dim]Repro:[/dim] {f.repro}")
            remediation = f.remediation or (r := _rem_lookup(f.check)) and r.summary
            if remediation:
                rprint(f"[dim]Remediation:[/dim] {remediation}")


@app.command()
def scan(
    target: str,
    out: str = typer.Option("scan.json", "--out", "-o"),
    passive: bool = typer.Option(False, "--passive"),
    rate: int = typer.Option(10, "--rate"),
):
    """discover -> fingerprint -> audit pipeline."""
    rprint(f"[bold yellow]Authorized testing only.[/bold yellow] You are responsible for permission to scan [cyan]{target}[/cyan].")
    result = asyncio.run(run_scan(target, passive=passive, rate=rate))
    Path(out).write_text(to_json(result))
    rprint(f"[green]wrote {out}[/green]  servers={len(result.servers)} findings={sum(len(v) for v in result.findings.values())}")


@app.command()
def configs():
    """Audit local stdio MCP configurations on this host."""
    entries = discover_configs()
    if not entries:
        rprint("[yellow]no MCP configs found in default paths[/yellow]")
        return
    table = Table("source", "name", "command", "args[0]")
    for e in entries:
        table.add_row(e.source_path, e.name, e.command, e.args[0] if e.args else "")
    rprint(table)


@app.command()
def report(scan_json: str, fmt: str = typer.Option("html", "--format"), out: str | None = typer.Option(None, "--out")):
    """Render a report from a scan.json."""
    data = Path(scan_json).read_text()
    sr = ScanResult.model_validate_json(data)
    if fmt == "json":
        text = to_json(sr)
        ext = "json"
    elif fmt == "md":
        text = to_markdown(sr)
        ext = "md"
    else:
        text = to_html(sr)
        ext = "html"
    out_path = out or scan_json.replace(".json", f".{ext}")
    Path(out_path).write_text(text)
    rprint(f"[green]wrote {out_path}[/green]")


@app.command()
def poc(
    scan_json: str,
    check: str = typer.Option(..., "--check", "-c", help="Check ID, e.g., INJECT-001"),
    out: str | None = typer.Option(None, "--out", "-o", help="Write to file (default: stdout)"),
):
    """Emit a coordinated-disclosure-ready PoC writeup for one finding."""
    data = Path(scan_json).read_text()
    sr = ScanResult.model_validate_json(data)
    text = render_poc(sr, check)
    if text.startswith("# No findings matched"):
        rprint(f"[red]{text.strip()}[/red]")
        raise typer.Exit(1)
    if out:
        Path(out).write_text(text)
        rprint(f"[green]wrote {out}[/green]")
    else:
        typer.echo(text)
