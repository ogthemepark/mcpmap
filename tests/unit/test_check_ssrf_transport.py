import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.ssrf_001 import Ssrf001ResourcesRead
from mcpmap.audit.checks.transport_001 import Transport001LegacySse


async def _ssrf_vuln(request):
    body = await request.json()
    if body.get("method") == "resources/read":
        uri = body["params"].get("uri", "")
        if uri.startswith("file://"):
            return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": "root:x:0:0:root:/root:/bin/bash\n"}]
            }})
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {"contents": []}})


@pytest.mark.asyncio
async def test_ssrf_001_fires_on_etc_passwd_read(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _ssrf_vuln)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    chk = Ssrf001ResourcesRead()
    assert chk.intrusive is True
    f = await chk.run(s)
    assert f and f.check == "MCP-RES-SSRF"
    assert "SSRF-001" in f.aliases


@pytest.mark.asyncio
async def test_transport_001_fires_when_legacy_sse():
    s = Server(url="http://x/sse", transport="http+sse")
    f = await Transport001LegacySse().run(s)
    assert f and f.check == "MCP-TRANSPORT-LEGACY-SSE"
    assert "TRANSPORT-001" in f.aliases


@pytest.mark.asyncio
async def test_transport_001_silent_for_streamable_http():
    s = Server(url="http://x/mcp", transport="streamable-http")
    assert await Transport001LegacySse().run(s) is None


@pytest.mark.asyncio
async def test_ssrf_001_does_not_false_positive_on_metadata_header_echo(aiohttp_server):
    """Regression: a server that echoes the URI back must not look like an SSRF hit
    just because the URI string contains 'Metadata-Flavor'-shaped text."""
    async def echo(request):
        body = await request.json()
        if body.get("method") == "resources/read":
            uri = body["params"].get("uri", "")
            return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": "Metadata-Flavor"}]
            }})
        return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {}})

    app = web.Application(); app.router.add_post("/mcp", echo)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Ssrf001ResourcesRead().run(s)
    # Echoing the literal string "Metadata-Flavor" is not proof of GCP metadata access.
    # Should not fire on this fake.
    assert f is None, f"false positive: {f.evidence if f else None}"
