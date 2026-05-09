from aiohttp import web
import asyncio


async def sse(request):
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
    await resp.prepare(request)
    await resp.write(b"event: endpoint\ndata: /messages\n\n")
    await resp.write(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"mcp-legacy-sse\",\"version\":\"0.0.1\"}}}\n\n")
    await asyncio.sleep(60)
    return resp


async def messages(request):
    body = await request.json(); rid = body.get("id", 1); m = body.get("method")
    if m == "tools/list":
        return web.json_response({"jsonrpc":"2.0","id":rid,"result":{"tools":[]}})
    return web.json_response({"jsonrpc":"2.0","id":rid,"error":{"code":-32601}})


app = web.Application()
app.router.add_get("/sse", sse)
app.router.add_post("/messages", messages)
web.run_app(app, host="0.0.0.0", port=8000)
