import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.auth_002 import Auth002AudienceBinding


async def _accept_any_token(request):
    # broken: ignores Authorization header
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


async def _enforce_token(request):
    if request.headers.get("Authorization") != "Bearer correct":
        return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001}}, status=401)
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


@pytest.mark.asyncio
async def test_fires_when_unrelated_token_accepted(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _accept_any_token)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth002AudienceBinding().run(s)
    assert f is not None and f.check == "AUTH-002"


@pytest.mark.asyncio
async def test_silent_when_token_validated(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _enforce_token)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    assert await Auth002AudienceBinding().run(s) is None
