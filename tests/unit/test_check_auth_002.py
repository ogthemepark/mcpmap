import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.auth_002 import Auth002AudienceBinding


async def _enforce_token(request):
    if request.headers.get("Authorization") != "Bearer correct":
        return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001}}, status=401)
    return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})



@pytest.mark.asyncio
async def test_silent_when_token_validated(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _enforce_token)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    assert await Auth002AudienceBinding().run(s) is None


@pytest.mark.asyncio
async def test_auth_002_silent_when_server_has_no_auth_at_all(aiohttp_server):
    """Regression: an unauthenticated server must not be flagged for 'audience binding'.
    AUTH-002 is only meaningful when the server *requires* a token but accepts the wrong one."""
    from aiohttp import web

    async def no_auth(request):
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", no_auth)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth002AudienceBinding().run(s)
    assert f is None, f"AUTH-002 false-positive on no-auth server: {f}"


@pytest.mark.asyncio
async def test_auth_002_fires_when_token_required_but_audience_unchecked(aiohttp_server):
    """AUTH-002 should fire when no-token = 401 but bogus-token = 200."""
    from aiohttp import web

    async def lax_auth(request):
        if not request.headers.get("Authorization"):
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "auth required"}}, status=401)
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", lax_auth)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth002AudienceBinding().run(s)
    assert f is not None and f.check == "MCP-AUTH-AUDIENCE-MISBOUND"
    assert "AUTH-002" in f.aliases
