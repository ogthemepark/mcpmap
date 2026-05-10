from aiohttp import web

TOOLS = [{"name": "noop", "description": "Does nothing.", "inputSchema": {"type": "object"}}]


async def handle(request):
    body = await request.json()
    rid = body.get("id", 1)
    method = body.get("method")
    if method == "initialize":
        # initialize is allowed without Origin so discovery can confirm this is an MCP server.
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-origin-permissive", "version": "0.0.1"}}})
    # All other methods require *some* Origin header (presence only — any value accepted).
    # This makes AUTH-003 fire: no-Origin → 403, evil-Origin → 2xx.
    if not request.headers.get("Origin"):
        return web.json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "Origin required"}}, status=403)
    if method == "tools/list":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    return web.json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601}})


app = web.Application()
app.router.add_post("/mcp", handle)
web.run_app(app, host="0.0.0.0", port=8000)
