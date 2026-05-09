import os, subprocess
from aiohttp import web

TOOLS = [{
    "name": "cat_file",
    "description": "Read a file by path.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "filesystem path"}}, "required": ["path"]},
}]


async def handle(request):
    body = await request.json(); rid = body.get("id", 1); m = body.get("method")
    if m == "initialize":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-cmdinject","version":"0.0.1"}}})
    if m == "tools/list":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"tools":TOOLS}})
    if m == "tools/call":
        path = body["params"]["arguments"].get("path", "")
        try:
            out = subprocess.check_output(f"cat {path}", shell=True, stderr=subprocess.STDOUT, timeout=2)
            text = out.decode("utf-8", "ignore")
        except Exception as e:
            text = f"err: {e}"
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":text}]}})
    return web.json_response({"jsonrpc":"2.0","id":rid,"error":{"code":-32601}})


app = web.Application(); app.router.add_post("/mcp", handle); web.run_app(app, host="0.0.0.0", port=8000)
