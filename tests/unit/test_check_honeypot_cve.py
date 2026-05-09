import pytest
from aiohttp import web
from mcpmap.models import Server, ServerInfo
from mcpmap.audit.checks.honeypot_001 import Honeypot001
from mcpmap.audit.checks.cve_001 import Cve001VersionMatch


@pytest.fixture
async def honeypot_srv(aiohttp_server):
    app = web.Application()
    async def handle(request):
        return web.json_response(
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
            headers={"Mcp-Session-Id": "fixed-honey-id-12345"},
        )
    app.router.add_post("/mcp", handle)
    return await aiohttp_server(app)


@pytest.mark.asyncio
async def test_honeypot_fires_on_repeated_session_id(honeypot_srv):
    s = Server(url=f"http://{honeypot_srv.host}:{honeypot_srv.port}/mcp")
    f = await Honeypot001().run(s)
    assert f and f.check == "HONEYPOT-001"


@pytest.mark.asyncio
async def test_cve_001_matches_vulnerable_version():
    s = Server(
        url="http://x/mcp",
        fingerprint_id="mcp-remote",
        server_info=ServerInfo(name="mcp-remote", version="0.1.10"),
    )
    f = await Cve001VersionMatch().run(s)
    assert f and "CVE-2025-6514" in (f.cve or "")


@pytest.mark.asyncio
async def test_cve_001_silent_on_patched_version():
    s = Server(
        url="http://x/mcp",
        fingerprint_id="mcp-remote",
        server_info=ServerInfo(name="mcp-remote", version="0.1.16"),
    )
    assert await Cve001VersionMatch().run(s) is None
