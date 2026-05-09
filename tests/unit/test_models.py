from mcpmap.models import Target, Server, Finding, Severity, ScanResult


def test_target_minimal():
    t = Target(host="10.0.0.5", port=8000)
    assert t.url("http", "/mcp") == "http://10.0.0.5:8000/mcp"


def test_finding_serializes():
    f = Finding(
        check="AUTH-001",
        severity=Severity.HIGH,
        title="unauth tools/list",
        cvss=7.5,
        evidence={"request": "POST /mcp", "response": "200 OK"},
        repro="curl ...",
    )
    d = f.model_dump()
    assert d["severity"] == "high"
    assert d["cvss"] == 7.5


def test_scan_result_round_trip():
    s = Server(url="http://10.0.0.5:8000/mcp", transport="streamable-http")
    sr = ScanResult(scan_id="test-1", servers=[s])
    j = sr.model_dump_json()
    sr2 = ScanResult.model_validate_json(j)
    assert sr2.servers[0].url == s.url


def test_finding_remediation_optional_default_none():
    from mcpmap.models import Finding, Severity
    f = Finding(check="X", severity=Severity.LOW, cvss=1.0, title="t")
    assert f.remediation is None

def test_finding_remediation_round_trips():
    from mcpmap.models import Finding, Severity
    f = Finding(check="X", severity=Severity.LOW, cvss=1.0, title="t",
                remediation="Reject the request.")
    j = f.model_dump_json()
    assert "Reject the request" in j
