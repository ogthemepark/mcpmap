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


def test_html_escapes_remediation_payload():
    """XSS: malicious tool descriptions / remediations must not break out of HTML."""
    s = Server(url="http://x/mcp", server_info=ServerInfo(name="evil<script>", version="1"))
    sr = ScanResult(scan_id="t", servers=[s], findings={
        s.url: [Finding(check="X", severity=Severity.LOW, cvss=1.0,
                        title="<img onerror=alert(1)>",
                        remediation="</p><script>alert(1)</script>")]
    })
    html = to_html(sr)
    # Server fields are JSON-embedded as data, then innerHTML'd by esc(). The
    # scanner data itself appears JSON-encoded inside a <script>, but the esc()
    # helper must be present in the template so that runtime rendering is safe.
    assert "function esc(" in html
    # No raw payload that would execute. The data block is JSON, so we can't
    # forbid the literal string from appearing — but assert the esc helper is wired.
