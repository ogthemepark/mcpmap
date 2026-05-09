import os
import pytest
from typer.testing import CliRunner
from mcpmap.cli import app

runner = CliRunner()
pytestmark = pytest.mark.skipif(os.environ.get("MCPMAP_LAB", "off") != "on", reason="lab not running")


def test_scan_writes_json(tmp_path):
    out = tmp_path / "scan.json"
    r = runner.invoke(app, ["scan", "127.0.0.1", "--out", str(out)])
    assert r.exit_code == 0
    assert out.exists()
    text = out.read_text()
    assert "AUTH-001" in text or '"servers"' in text


def test_report_html_self_contained(tmp_path):
    out = tmp_path / "scan.json"
    runner.invoke(app, ["scan", "127.0.0.1", "--out", str(out)])
    html_out = tmp_path / "scan.html"
    r = runner.invoke(app, ["report", str(out), "--format", "html", "--out", str(html_out)])
    assert r.exit_code == 0
    assert html_out.exists()
    body = html_out.read_text()
    assert "https://cdn" not in body
