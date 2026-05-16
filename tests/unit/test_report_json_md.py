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


def test_markdown_renders_remediation():
    from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
    from mcpmap.report.markdown_out import to_markdown
    s = Server(url="http://x/mcp", server_info=ServerInfo(name="x", version="1"))
    sr = ScanResult(scan_id="t", servers=[s], findings={
        s.url: [Finding(check="AUTH-001", severity=Severity.HIGH, cvss=7.5,
                        title="t", remediation="Require auth.")]
    })
    md = to_markdown(sr)
    assert "Require auth." in md


def test_markdown_strips_newlines_from_remediation():
    from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
    from mcpmap.report.markdown_out import to_markdown
    s = Server(url="http://x/mcp", server_info=ServerInfo(name="x", version="1"))
    sr = ScanResult(scan_id="t", servers=[s], findings={
        s.url: [Finding(check="X", severity=Severity.LOW, cvss=1.0, title="t",
                        remediation="line1\n```\nline2")]
    })
    md = to_markdown(sr)
    # The newline + fence inside remediation must NOT survive verbatim
    # (otherwise it would break out of the surrounding structure).
    assert "line1\n```" not in md
    assert "line1" in md and "line2" in md


def test_markdown_renders_remediation_from_yaml():
    from mcpmap.models import ScanResult, Server, Finding, Severity
    from mcpmap.report.markdown_out import to_markdown
    sr = ScanResult(scan_id="x", servers=[Server(url="http://x/mcp")],
                    findings={"http://x/mcp": [Finding(check="MCP-AUTH-UNAUTH-LIST", severity=Severity.HIGH, title="t")]})
    md = to_markdown(sr)
    assert "OAuth 2.1" in md  # comes from remediations.yaml
    assert "AUTH-001" in md   # legacy alias shown


def test_markdown_indents_correlated_findings():
    from mcpmap.models import ScanResult, Server, Finding, Severity
    from mcpmap.report.markdown_out import to_markdown
    sr = ScanResult(scan_id="x", servers=[Server(url="http://x/mcp")], findings={"http://x/mcp": [
        Finding(check="MCP-AUTH-UNAUTH-LIST", severity=Severity.HIGH, title="root"),
        Finding(check="MCP-AUTH-AUDIENCE-MISBOUND", severity=Severity.HIGH, title="child", related_to="MCP-AUTH-UNAUTH-LIST"),
    ]})
    md = to_markdown(sr)
    assert "↳" in md or "  -" in md   # some visible indent for the child
