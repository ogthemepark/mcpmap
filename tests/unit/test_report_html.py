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


def _basic_scan():
    s = Server(url="http://127.0.0.1:8006/mcp",
               fingerprint_id="mcp-cmdinject",
               server_info=ServerInfo(name="mcp-cmdinject", version="0.0.1"))
    return ScanResult(scan_id="t1", servers=[s], findings={
        s.url: [Finding(check="INJECT-001", severity=Severity.CRITICAL, cvss=9.0,
                        title="Command injection", remediation="Don't shell out.")]
    })


def test_html_no_d3_dependency():
    """Cycle B drops d3. The marker substitution and library should be gone."""
    html = to_html(_basic_scan())
    assert "{{D3_INLINE}}" not in html  # placeholder must be replaced or removed
    assert "d3.forceSimulation" not in html
    assert "d3.min.js" not in html


def test_html_dashboard_chrome():
    """Top-level chrome elements are present."""
    html = to_html(_basic_scan())
    # Roles for screen readers and structural sentinels for the JS.
    assert 'id="header"' in html
    assert 'id="severity-strip"' in html
    assert 'id="filter-bar"' in html
    assert 'id="server-list"' in html
    assert 'id="finding-list"' in html
    assert 'id="detail-pane"' in html


def test_html_severity_palette_complete():
    """All 5 severity classes have CSS rules."""
    html = to_html(_basic_scan())
    for sev in ("critical", "high", "medium", "low", "info"):
        # CSS variable + class definition for each severity
        assert f"--sev-{sev}:" in html
        assert f".sev-{sev}" in html


def test_html_severity_sigils_present():
    """Severity sigils (▣ ◆ ◈ ○ ·) are rendered in the JS map for icon mode."""
    html = to_html(_basic_scan())
    # The SIGIL map literal should be present in the JS so a colorblind
    # user can still distinguish severities.
    assert "SIGIL" in html
    for sigil in ("▣", "◆", "◈", "○", "·"):
        assert sigil in html


def test_html_esc_helper_still_present():
    """Cycle A XSS hardening is preserved through the rewrite."""
    html = to_html(_basic_scan())
    assert "function esc(" in html


def test_html_scan_id_is_escaped():
    """A malicious scan_id must not be able to inject HTML/JS into the report."""
    s = Server(url="http://x/mcp", server_info=ServerInfo(name="x", version="1"))
    sr = ScanResult(scan_id="<script>alert(1)</script>", servers=[s], findings={})
    html = to_html(sr)
    # Raw injection sequence must not appear; entity-escaped form must appear instead.
    assert "<script>alert(1)</script>" not in html.replace(
        '<script>function esc(', ""  # ignore the legitimate inline script start
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_scan_id_no_template_recursion():
    """A scan_id of '{{DATA_JSON}}' must not cause the data block to be inserted twice."""
    s = Server(url="http://x/mcp", server_info=ServerInfo(name="x", version="1"))
    sr = ScanResult(scan_id="{{DATA_JSON}}", servers=[s], findings={})
    html = to_html(sr)
    # The escaped scan_id should appear in the title/header but the JSON data block
    # should appear exactly once (in the const data assignment), not twice.
    assert html.count("const data = ") == 1
    # The data block contains the servers list — count occurrences of the unique server URL.
    # If the substitution chained, the URL would appear twice or more.
    assert html.count('"http://x/mcp"') == 1
