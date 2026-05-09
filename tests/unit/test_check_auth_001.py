import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.auth_001 import Auth001UnauthToolsList


async def _tools_list_ok(request):
    return web.json_response({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": [{"name": "echo", "description": "echoes"}]},
    })


async def _unauthorized(request):
    return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "auth"}}, status=401)


@pytest.fixture
async def open_srv(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _tools_list_ok)
    return await aiohttp_server(app)


@pytest.fixture
async def auth_srv(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _unauthorized)
    return await aiohttp_server(app)


@pytest.mark.asyncio
async def test_fires_on_unauth_tools_list(open_srv):
    s = Server(url=f"http://{open_srv.host}:{open_srv.port}/mcp")
    f = await Auth001UnauthToolsList().run(s)
    assert f is not None
    assert f.check == "AUTH-001"
    assert f.severity == "high"


@pytest.mark.asyncio
async def test_silent_on_auth_required(auth_srv):
    s = Server(url=f"http://{auth_srv.host}:{auth_srv.port}/mcp")
    f = await Auth001UnauthToolsList().run(s)
    assert f is None
