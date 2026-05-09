import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.auth_003 import Auth003OriginValidation


async def _accept_any_origin(request):
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {}})


async def _reject_evil_origin(request):
    if request.headers.get("Origin") == "https://evil.example":
        return web.Response(status=403)
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {}})


@pytest.mark.asyncio
async def test_fires_on_permissive_origin(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _accept_any_origin)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f and f.check == "AUTH-003"


@pytest.mark.asyncio
async def test_silent_when_evil_origin_rejected(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _reject_evil_origin)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    assert await Auth003OriginValidation().run(s) is None
