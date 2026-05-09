from __future__ import annotations
import typer
from rich import print as rprint
from mcpmap import __version__

app = typer.Typer(
    name="mcpmap",
    help="Nmap for MCP servers — discover, fingerprint, audit.",
    no_args_is_help=True,
)


def _version_cb(value: bool):
    if value:
        rprint(f"mcpmap [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(None, "--version", callback=_version_cb, is_eager=True),
):
    """mcpmap — Model Context Protocol vulnerability scanner."""


@app.command()
def discover(target: str = typer.Argument(..., help="CIDR | host | URL | shodan:<query> | file:<path>")):
    """Find MCP servers (active scan, Shodan, or local config)."""
    rprint(f"[yellow]TODO[/yellow] discover {target}")


@app.command()
def fingerprint(url: str):
    """Identify framework, version, capabilities for one MCP URL."""
    rprint(f"[yellow]TODO[/yellow] fingerprint {url}")


@app.command()
def audit(
    url: str,
    passive: bool = typer.Option(False, "--passive", help="Skip intrusive checks (INJECT, SSRF)."),
):
    """Run vulnerability checks against one MCP URL."""
    rprint(f"[yellow]TODO[/yellow] audit {url} (passive={passive})")


@app.command()
def scan(
    target: str,
    out: str = typer.Option("scan.json", "--out", "-o"),
    passive: bool = typer.Option(False, "--passive"),
    rate: int = typer.Option(10, "--rate", help="Per-host requests per second."),
):
    """discover → fingerprint → audit pipeline."""
    rprint(f"[yellow]TODO[/yellow] scan {target} -> {out}")


@app.command()
def configs():
    """Audit local stdio MCP configurations on this host."""
    rprint("[yellow]TODO[/yellow] configs")


@app.command()
def report(scan_json: str, fmt: str = typer.Option("html", "--format")):
    """Render a report from a scan.json."""
    rprint(f"[yellow]TODO[/yellow] report {scan_json} ({fmt})")
