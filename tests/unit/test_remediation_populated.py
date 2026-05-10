"""
After Task 4, checks no longer set inline remediation strings — the renderer
(Task 7) pulls them from data/remediations.yaml via audit.remediations.lookup().
These tests verify that every check that used to carry an inline remediation has a
corresponding entry in the YAML, and that lookup() returns a non-empty summary for it.
"""
import pytest
from mcpmap.audit.remediations import lookup
from mcpmap.models import Server, Tool, ServerInfo


def test_auth_unauth_list_remediation_in_yaml():
    r = lookup("MCP-AUTH-UNAUTH-LIST")
    assert r and len(r.summary) > 20


def test_auth_audience_misbound_remediation_in_yaml():
    r = lookup("MCP-AUTH-AUDIENCE-MISBOUND")
    assert r and len(r.summary) > 20


def test_auth_origin_misvalidated_remediation_in_yaml():
    r = lookup("MCP-AUTH-ORIGIN-MISVALIDATED")
    assert r and len(r.summary) > 20


def test_tpa_desc_inject_remediation_in_yaml():
    r = lookup("MCP-TPA-DESC-INJECT")
    assert r and len(r.summary) > 20


def test_tpa_unicode_smuggle_remediation_in_yaml():
    r = lookup("MCP-TPA-UNICODE-SMUGGLE")
    r2 = lookup("POISON-002")  # legacy alias still works
    assert r and "NFKC" in r.summary
    assert r2 and r2.summary == r.summary


def test_transport_legacy_sse_remediation_in_yaml():
    r = lookup("MCP-TRANSPORT-LEGACY-SSE")
    assert r and "streamable-http" in r.summary


def test_cve_version_match_remediation_in_yaml():
    r = lookup("MCP-CVE-VERSION-MATCH")
    assert r and "patched" in r.summary.lower()


@pytest.mark.asyncio
async def test_poison_001_does_not_set_inline_remediation():
    """Checks must leave remediation=None; renderer fills it."""
    from mcpmap.audit.checks.poison_001 import Poison001ToolDescriptionRegex
    s = Server(url="http://x/mcp", tools=[
        Tool(name="add", description="<IMPORTANT>x</IMPORTANT>")
    ])
    f = await Poison001ToolDescriptionRegex().run(s)
    assert f is not None
    assert f.remediation is None


@pytest.mark.asyncio
async def test_transport_001_does_not_set_inline_remediation():
    """Checks must leave remediation=None; renderer fills it."""
    from mcpmap.audit.checks.transport_001 import Transport001LegacySse
    s = Server(url="http://x/sse", transport="http+sse")
    f = await Transport001LegacySse().run(s)
    assert f is not None
    assert f.remediation is None


@pytest.mark.asyncio
async def test_cve_001_does_not_set_inline_remediation():
    """Checks must leave remediation=None; renderer fills it."""
    from mcpmap.audit.checks.cve_001 import Cve001VersionMatch
    s = Server(url="http://x/mcp", fingerprint_id="mcp-remote",
               server_info=ServerInfo(name="mcp-remote", version="0.1.10"))
    f = await Cve001VersionMatch().run(s)
    assert f is not None
    assert f.remediation is None
