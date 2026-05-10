import pytest
from aiohttp import web
from mcpmap.models import Server
from mcpmap.audit.checks.auth_003 import Auth003OriginValidation


async def _reject_no_origin_accept_any_origin(request):
    """True AUTH-003 positive: requires some Origin but doesn't validate which."""
    origin = request.headers.get("Origin")
    if not origin:
        return web.Response(status=403)
    body = await request.json()
    return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {}})


async def _reject_evil_origin(request):
    origin = request.headers.get("Origin")
    if not origin:
        return web.Response(status=403)           # requires Origin
    if origin == "https://evil.example":
        return web.Response(status=403)           # rejects the evil one too
    body = await request.json()
    return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {}})


@pytest.mark.asyncio
async def test_fires_on_permissive_origin(aiohttp_server):
    """AUTH-003 fires when server requires Origin but accepts attacker-controlled values."""
    app = web.Application()
    app.router.add_post("/mcp", _reject_no_origin_accept_any_origin)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f and f.check == "MCP-AUTH-ORIGIN-MISVALIDATED"
    assert "AUTH-003" in f.aliases


@pytest.mark.asyncio
async def test_silent_when_evil_origin_rejected(aiohttp_server):
    app = web.Application()
    app.router.add_post("/mcp", _reject_evil_origin)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    assert await Auth003OriginValidation().run(s) is None


@pytest.mark.asyncio
async def test_auth_003_silent_when_server_has_no_auth_at_all(aiohttp_server):
    """Regression: a fully open server is AUTH-001, not AUTH-003.
    Origin validation is only meaningful when the server cares about origins."""
    async def open_server(request):
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", open_server)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f is None, f"AUTH-003 false-positive on no-auth server: {f}"


@pytest.mark.asyncio
async def test_auth_003_fires_when_no_origin_rejected_but_evil_accepted(aiohttp_server):
    async def origin_lax(request):
        origin = request.headers.get("Origin")
        if not origin:
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "origin required"}}, status=403)
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", origin_lax)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f is not None and f.check == "MCP-AUTH-ORIGIN-MISVALIDATED"
    assert "AUTH-003" in f.aliases
