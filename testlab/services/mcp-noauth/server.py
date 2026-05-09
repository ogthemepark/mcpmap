from aiohttp import web

TOOLS = [{"name": "echo", "description": "Echoes input.", "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}}]


async def handle(request):
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)
    if method == "initialize":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-noauth", "version": "0.0.1"},
        }})
    if method == "tools/list":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    return web.json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})


app = web.Application()
app.router.add_post("/mcp", handle)
web.run_app(app, host="0.0.0.0", port=8000)
