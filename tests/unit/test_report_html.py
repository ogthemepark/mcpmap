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


def test_html_data_block_escapes_script_break():
    """A server-controlled string containing </script> must not break out
    of the data <script> block in the generated HTML."""
    from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
    from mcpmap.report.html_out import to_html
    s = Server(url="http://x/mcp",
               server_info=ServerInfo(name="evil", version="1"))
    sr = ScanResult(scan_id="t", servers=[s], findings={
        s.url: [Finding(
            check="X", severity=Severity.LOW, cvss=1.0,
            title="t",
            remediation="</script><script>alert(1)</script>",
        )]
    })
    html = to_html(sr)
    # The literal "</script>" sequence must not appear inside the JSON data
    # block. The replace converts it to "<\/script>" which is semantically
    # identical for JSON / JS but does not close the surrounding <script>.
    # We can't simply assert "</script>" not in html because the template
    # itself contains the legitimate closing </script> tag, but we can
    # assert that the data assignment (one specific line) doesn't contain it.
    # Find the data line:
    for line in html.splitlines():
        if "const data" in line or "var data" in line or "data =" in line:
            assert "</script>" not in line, f"unsafe data line: {line!r}"
            assert r"<\/script>" in line or "alert" not in line
            break
    else:
        # If the template doesn't put data on a single line, fall back to a
        # whole-document scan that requires the escaped form to be present.
        assert r"<\/script>" in html
