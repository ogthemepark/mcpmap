from mcpmap.models import Finding, Severity
from mcpmap.audit.correlate import rollup


def _f(check, sev=Severity.HIGH):
    return Finding(check=check, severity=sev, title=check)


def test_rollup_links_audience_and_origin_to_unauth_when_unauth_present():
    fs = [
        _f("MCP-AUTH-UNAUTH-LIST"),
        _f("MCP-AUTH-AUDIENCE-MISBOUND"),
        _f("MCP-AUTH-ORIGIN-MISVALIDATED"),
        _f("MCP-TOOL-CMD-INJECT"),
    ]
    out = rollup(fs)
    by_id = {f.check: f for f in out}
    assert by_id["MCP-AUTH-AUDIENCE-MISBOUND"].related_to == "MCP-AUTH-UNAUTH-LIST"
    assert by_id["MCP-AUTH-ORIGIN-MISVALIDATED"].related_to == "MCP-AUTH-UNAUTH-LIST"
    assert by_id["MCP-AUTH-UNAUTH-LIST"].related_to is None
    assert by_id["MCP-TOOL-CMD-INJECT"].related_to is None  # unrelated → standalone


def test_rollup_no_op_when_no_root():
    fs = [_f("MCP-AUTH-AUDIENCE-MISBOUND"), _f("MCP-TOOL-CMD-INJECT")]
    out = rollup(fs)
    assert all(f.related_to is None for f in out)
