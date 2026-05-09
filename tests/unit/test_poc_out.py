from mcpmap.models import ScanResult, Server, Finding, Severity, ServerInfo
from mcpmap.report.poc_out import render_poc


def _scan():
    s = Server(url="http://127.0.0.1:8006/mcp",
               fingerprint_id="mcp-cmdinject",
               server_info=ServerInfo(name="mcp-cmdinject", version="0.0.1"))
    return ScanResult(scan_id="t1", servers=[s], findings={
        s.url: [Finding(
            check="INJECT-001",
            severity=Severity.CRITICAL,
            cvss=9.0,
            title="Command injection via tool argument",
            evidence={"canary": "MCPMAP_CANARY_abc",
                      "hits": [{"tool": "cat_file", "arg": "path",
                                "payload": "; echo MCPMAP_CANARY_abc"}]},
            repro="Re-send the recorded payload via curl.",
            remediation="Never pass tool arguments to a shell."
        )]
    })


def test_poc_renders_target_and_severity():
    out = render_poc(_scan(), "INJECT-001")
    assert "INJECT-001" in out
    assert "127.0.0.1:8006" in out
    assert "CRITICAL" in out.upper()
    assert "CVSS 9.0" in out


def test_poc_includes_curl_block_with_canary():
    out = render_poc(_scan(), "INJECT-001")
    assert "```bash" in out
    assert "curl" in out
    assert "MCPMAP_CANARY_abc" in out
    assert "tools/call" in out


def test_poc_includes_remediation():
    out = render_poc(_scan(), "INJECT-001")
    assert "## Remediation" in out
    assert "Never pass tool arguments to a shell." in out


def test_poc_no_match_returns_empty_with_message():
    out = render_poc(_scan(), "DOES-NOT-EXIST")
    assert "no findings" in out.lower()
