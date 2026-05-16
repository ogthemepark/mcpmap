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


@pytest.mark.asyncio
async def test_active_discover_finds_sse_server(aiohttp_server):
    """Regression: legacy SSE servers respond to GET /sse, not POST /sse.
    active_discover must still report them as MCP servers."""
    from aiohttp import web

    async def sse_handler(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(
            b'event: message\ndata: {"jsonrpc":"2.0","id":0,"result":'
            b'{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},'
            b'"serverInfo":{"name":"sse-fake","version":"0.0.1"}}}\n\n'
        )
        return resp

    app = web.Application()
    app.router.add_get("/sse", sse_handler)
    srv = await aiohttp_server(app)

    from mcpmap.discover.active import active_discover
    targets = await active_discover(srv.host, ports=[srv.port])
    assert any(t.path_hint == "/sse" for t in targets), (
        f"expected /sse target, got: {[(t.port, t.path_hint) for t in targets]}"
    )
