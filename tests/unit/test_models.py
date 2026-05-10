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


from mcpmap.models import Finding, Severity, Confidence, Evidence


def test_finding_accepts_confidence_cwe_and_vector():
    f = Finding(
        check="MCP-AUTH-UNAUTH-LIST",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cvss=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-306",
        title="x",
    )
    assert f.confidence is Confidence.HIGH
    assert f.cwe == "CWE-306"
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.aliases == []
    assert f.related_to is None


def test_finding_evidence_is_typed():
    e = Evidence(request={"a": 1}, response_excerpt="ok", artifacts={"k": "v"})
    f = Finding(check="X", severity=Severity.LOW, title="t", evidence=e)
    assert f.evidence.request == {"a": 1}
    # Backwards-compat: still accepts a plain dict for evidence
    f2 = Finding(check="X", severity=Severity.LOW, title="t", evidence={"foo": "bar"})
    assert f2.evidence.artifacts == {"foo": "bar"}
