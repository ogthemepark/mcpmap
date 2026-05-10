import pytest
from aiohttp import web
from mcpmap.discover.handshake import initialize


async def _mcp(request):
    body = await request.json()
    assert body["method"] == "initialize"
    return web.json_response({
        "jsonrpc": "2.0",
        "id": body["id"],
        "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-mcp", "version": "0.0.1"},
        },
    })


@pytest.fixture
async def srv(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _mcp)
    return await aiohttp_server(app)


@pytest.mark.asyncio
async def test_initialize_returns_server_info(srv):
    url = f"http://{srv.host}:{srv.port}/mcp"
    res = await initialize(url)
    assert res is not None
    assert res["serverInfo"]["name"] == "fake-mcp"
    assert res["protocolVersion"] == "2025-11-25"


@pytest.mark.asyncio
async def test_initialize_returns_none_for_non_mcp(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", lambda r: web.Response(text="hi"))
    srv = await aiohttp_server(app)
    url = f"http://{srv.host}:{srv.port}/mcp"
    assert await initialize(url) is None


@pytest.mark.asyncio
async def test_initialize_reports_streamable_http_transport(aiohttp_server):
    async def h(request):
        return web.json_response({
            "jsonrpc": "2.0", "id": 1,
            "result": {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "x", "version": "0"}},
        })
    app = web.Application(); app.router.add_post("/mcp", h)
    srv = await aiohttp_server(app)
    res = await initialize(f"http://{srv.host}:{srv.port}/mcp")
    assert res is not None
    assert res.get("_mcpmap_transport") == "streamable-http"


@pytest.mark.asyncio
async def test_initialize_reports_http_sse_transport(aiohttp_server):
    """POST /mcp returns SSE stream — Content-Type: text/event-stream."""
    async def h(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(
            b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"x","version":"0"}}}\n\n'
        )
        return resp
    app = web.Application(); app.router.add_post("/mcp", h)
    srv = await aiohttp_server(app)
    res = await initialize(f"http://{srv.host}:{srv.port}/mcp")
    assert res is not None
    assert res.get("_mcpmap_transport") == "http+sse"


@pytest.mark.asyncio
async def test_initialize_reports_http_sse_transport_get_only(aiohttp_server):
    """GET /sse streams SSE (POST returns 405) — legacy http+sse transport."""
    async def post_h(request):
        return web.Response(status=405)

    async def get_h(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(
            b'event: endpoint\ndata: /messages\n\n'
            b'event: message\ndata: {"jsonrpc":"2.0","id":0,"result":'
            b'{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"x","version":"0"}}}\n\n'
        )
        return resp

    app = web.Application()
    app.router.add_post("/sse", post_h)
    app.router.add_get("/sse", get_h)
    srv = await aiohttp_server(app)
    res = await initialize(f"http://{srv.host}:{srv.port}/sse")
    assert res is not None
    assert res.get("_mcpmap_transport") == "http+sse"
