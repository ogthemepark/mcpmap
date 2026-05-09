from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
from mcpmap.report.json_out import to_json
from mcpmap.report.markdown_out import to_markdown


def _fixture():
    s = Server(url="http://10.0.0.5:8000/mcp", fingerprint_id="filesystem-mcp",
               server_info=ServerInfo(name="filesystem-mcp", version="1.2.0"))
    return ScanResult(scan_id="t1", servers=[s], findings={
        s.url: [Finding(check="AUTH-001", severity=Severity.HIGH, cvss=7.5, title="x")]
    })


def test_json_round_trip():
    sr = _fixture()
    j = to_json(sr)
    assert "AUTH-001" in j
    assert "filesystem-mcp" in j


def test_markdown_contains_severity_and_url():
    sr = _fixture()
    md = to_markdown(sr)
    assert "AUTH-001" in md
    assert "10.0.0.5:8000" in md
    assert "## " in md
