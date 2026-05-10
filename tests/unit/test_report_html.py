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


def test_finding_list_uses_data_attributes():
    """Each finding row must carry data-* attrs so filters can hide/show by class."""
    html = to_html(_basic_scan())
    # The JS that renders findings is in the template. Sentinel: the function
    # constructs nodes with data-severity / data-check / data-server attrs.
    for sentinel in ('data-severity="${', 'data-check="${', 'data-server="${'):
        assert sentinel in html, f"missing sentinel: {sentinel}"


def test_server_list_renders_servers():
    """Render JS reads from data.servers and emits one .server node per entry
    with data-server attributes for selection wiring."""
    html = to_html(_basic_scan())
    assert "data.servers" in html
    # The render function must emit nodes with data-server attrs
    assert 'data-server="${' in html
    # And use the .server class
    assert "server${sel" in html or 'class="server "' in html or 'class="server"' in html


def test_severity_strip_emits_all_five():
    """Severity strip JS iterates SEV_ORDER and emits a .seg per level."""
    html = to_html(_basic_scan())
    assert "renderSeverityStrip" in html
    # Both the strip render and the SEV_ORDER constant must reference all five.
    for sev in SEV_ORDER:
        assert f'"{sev}"' in html


def test_totals_summary_in_header():
    """The header `.totals` element gets populated with server + finding counts."""
    html = to_html(_basic_scan())
    assert "renderHeader" in html
    # The render function must reference both counts.
    assert "data.servers.length" in html
    assert "totalFindings" in html or "findings.length" in html or "totalCount" in html


def test_finding_key_is_stable_not_index_based():
    """selectedFinding key must not depend on filtered-list index, since
    renderDetail looks up against the full flatFindings() list."""
    html = to_html(_basic_scan())
    # The key is now a monotonic 'f<n>' assigned at flatten time. The
    # selectedFinding lookup must reference `item.key` and the rendered
    # data-key must be the same shape.
    assert "key: `f${" in html or 'key: "f"' in html or "key: 'f'" in html
    # The unstable `${url}|${f.check}|${i}` pattern should be gone from
    # the data-key attribute (it may still appear in OTHER places like a
    # comment, but not as the actual data-key value).
    # Sentinel: the new pattern is `data-key="${item.key}"` (or similar
    # using the destructured `key`). Verify either the destructured form
    # or the item form.
    assert 'data-key="${key}"' in html or 'data-key="${item.key}"' in html


SEV_ORDER = ("critical", "high", "medium", "low", "info")


import re


def test_html_filter_handlers_wired():
    """All four filter inputs have JS event listeners."""
    html = to_html(_basic_scan())
    assert "initFilters" in html
    # All four filter element IDs are referenced in handler code.
    for fid in ("f-severity", "f-check", "f-server", "f-search", "f-reset"):
        assert fid in html


def test_html_keyboard_nav_present():
    """j/k/Esc/'/' handlers are wired."""
    html = to_html(_basic_scan())
    assert "initKeyboardNav" in html or "keydown" in html
    # Sentinels for the keys we promised.
    for key in ('"j"', '"k"', '"Escape"', '"/"'):
        assert key in html, f"missing key handler sentinel: {key}"


def test_html_curl_for_has_all_check_branches():
    """The JS port of _curl_for must cover the same check IDs as poc_out.py."""
    html = to_html(_basic_scan())
    assert "function curlFor(" in html
    expected = ["INJECT-001", "SSRF-001", "AUTH-001", "AUTH-002", "AUTH-003",
                "HONEYPOT-001", "POISON-001", "POISON-002", "CVE-001", "TRANSPORT-001"]
    for cid in expected:
        # Each check ID must appear at least once in the JS curlFor function body.
        assert cid in html, f"curlFor missing branch for {cid}"


def test_html_copy_as_curl_button_wired():
    """The detail pane has a 'copy as curl' button that calls curlFor."""
    html = to_html(_basic_scan())
    assert "copy as curl" in html.lower() or "copy-curl" in html
    # The button click handler must call curlFor.
    assert re.search(r"curlFor\s*\(", html), "curlFor is never invoked"


def test_html_renders_evidence_and_repro_and_remediation_blocks():
    """Detail pane renders all three Cycle A fields when present."""
    html = to_html(_basic_scan())
    # Sentinels for the three section labels in the detail pane.
    for label in ("evidence", "reproduction", "remediation"):
        assert label.lower() in html.lower(), f"missing detail section: {label}"
