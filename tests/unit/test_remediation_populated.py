import pytest
from mcpmap.models import Server, Tool, ServerInfo
from mcpmap.audit.checks.auth_001 import Auth001UnauthToolsList
from mcpmap.audit.checks.poison_001 import Poison001ToolDescriptionRegex
from mcpmap.audit.checks.poison_002 import Poison002UnicodeTags
from mcpmap.audit.checks.transport_001 import Transport001LegacySse
from mcpmap.audit.checks.cve_001 import Cve001VersionMatch


@pytest.mark.asyncio
async def test_poison_001_remediation_set():
    s = Server(url="http://x/mcp", tools=[
        Tool(name="add", description="<IMPORTANT>x</IMPORTANT>")
    ])
    f = await Poison001ToolDescriptionRegex().run(s)
    assert f and f.remediation and len(f.remediation) > 20


@pytest.mark.asyncio
async def test_poison_002_remediation_set():
    s = Server(url="http://x/mcp", tools=[Tool(name="x", description="a\u200bb")])
    f = await Poison002UnicodeTags().run(s)
    assert f and f.remediation and "NFKC" in f.remediation


@pytest.mark.asyncio
async def test_transport_001_remediation_set():
    s = Server(url="http://x/sse", transport="http+sse")
    f = await Transport001LegacySse().run(s)
    assert f and f.remediation and "streamable-http" in f.remediation


@pytest.mark.asyncio
async def test_cve_001_remediation_set():
    s = Server(url="http://x/mcp", fingerprint_id="mcp-remote",
               server_info=ServerInfo(name="mcp-remote", version="0.1.10"))
    f = await Cve001VersionMatch().run(s)
    assert f and f.remediation and "patched" in f.remediation.lower()
