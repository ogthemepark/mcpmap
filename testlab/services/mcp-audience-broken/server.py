from aiohttp import web

TOOLS = [{"name": "ping", "description": "Pings.", "inputSchema": {"type": "object"}}]


async def handle(request):
    body = await request.json()
    rid = body.get("id", 1)
    method = body.get("method")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return web.json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": "auth required"}}, status=401)
    if method == "initialize":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-audience-broken", "version": "0.0.1"}}})
    if method == "tools/list":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    return web.json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601}})


app = web.Application()
app.router.add_post("/mcp", handle)
web.run_app(app, host="0.0.0.0", port=8000)
