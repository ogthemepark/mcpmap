from aiohttp import web


async def handle(request):
    body = await request.json(); rid = body.get("id", 1); m = body.get("method")
    headers = {"Mcp-Session-Id": "fixed-honey-id-12345"}
    if m == "initialize":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-honeypot","version":"0.0.1"}}}, headers=headers)
    if m == "tools/list":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"tools":[]}}, headers=headers)
    return web.json_response({"jsonrpc":"2.0","id":rid,"error":{"code":-32601}}, headers=headers)


app = web.Application(); app.router.add_post("/mcp", handle); web.run_app(app, host="0.0.0.0", port=8000)
