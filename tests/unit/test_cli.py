from typer.testing import CliRunner
from mcpmap.cli import app

runner = CliRunner()


def test_cli_help():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ("discover", "fingerprint", "audit", "scan", "configs", "report"):
        assert cmd in r.stdout


def test_cli_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    assert "0.1.0" in r.stdout
