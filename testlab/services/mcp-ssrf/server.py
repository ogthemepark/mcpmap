import urllib.parse, urllib.request
from aiohttp import web

TOOLS = []


async def handle(request):
    body = await request.json(); rid = body.get("id", 1); m = body.get("method")
    if m == "initialize":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}},"serverInfo":{"name":"mcp-ssrf","version":"0.0.1"}}})
    if m == "tools/list":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"tools":TOOLS}})
    if m == "resources/read":
        uri = body["params"].get("uri", "")
        try:
            with urllib.request.urlopen(uri, timeout=2) as resp:
                text = resp.read(8192).decode("utf-8", "ignore")
        except Exception as e:
            text = f"err: {e}"
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"contents":[{"uri":uri,"mimeType":"text/plain","text":text}]}})
    return web.json_response({"jsonrpc":"2.0","id":rid,"error":{"code":-32601}})


app = web.Application(); app.router.add_post("/mcp", handle); web.run_app(app, host="0.0.0.0", port=8000)
