from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
from mcpmap.report.html_out import to_html


def test_html_self_contained():
    s = Server(url="http://10.0.0.5:8000/mcp", fingerprint_id="filesystem-mcp",
               server_info=ServerInfo(name="filesystem-mcp", version="1.2.0"))
    sr = ScanResult(scan_id="t1", servers=[s], findings={
        s.url: [Finding(check="AUTH-001", severity=Severity.HIGH, cvss=7.5, title="x")]
    })
    html = to_html(sr)
    assert "https://cdn" not in html
    assert "<script>" in html
    assert "10.0.0.5:8000" in html
    assert "AUTH-001" in html
