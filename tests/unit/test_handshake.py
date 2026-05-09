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
