import pytest
from aiohttp import web
from mcpmap.discover.active import http_paths_alive, MCP_PATHS


async def _ok(request):
    return web.Response(text="ok")


@pytest.fixture
async def srv(aiohttp_server):
    app = web.Application()
    app.router.add_get("/mcp", _ok)
    app.router.add_get("/sse", _ok)
    return await aiohttp_server(app)


@pytest.mark.asyncio
async def test_http_paths_alive_finds_known_paths(srv):
    base = f"http://{srv.host}:{srv.port}"
    alive = await http_paths_alive(base, paths=MCP_PATHS, timeout=2.0)
    assert "/mcp" in alive
    assert "/sse" in alive
    assert "/api/mcp" not in alive
