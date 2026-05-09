import pytest
from aiohttp import web
from mcpmap.models import Server, Tool
from mcpmap.audit.checks.inject_001 import Inject001CanaryEcho


def _vuln_handler(request_body):
    method = request_body.get("method")
    if method == "tools/call":
        args = request_body["params"].get("arguments", {})
        path = args.get("path", "")
        if "$(echo" in path or "; echo" in path:
            import re
            m = re.search(r"MCPMAP_CANARY_[a-f0-9-]+", path)
            output = m.group(0) if m else ""
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": f"file: foo\n{output}"}]}}
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}


@pytest.fixture
async def vuln_srv(aiohttp_server):
    app = web.Application()
    async def handle(request):
        body = await request.json()
        return web.json_response(_vuln_handler(body))
    app.router.add_post("/mcp", handle)
    return await aiohttp_server(app)


@pytest.mark.asyncio
async def test_inject_001_fires_on_canary_echo(vuln_srv):
    s = Server(
        url=f"http://{vuln_srv.host}:{vuln_srv.port}/mcp",
        tools=[Tool(name="cat_file", description="Read a file by path", input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "filesystem path"}},
            "required": ["path"],
        })],
    )
    chk = Inject001CanaryEcho()
    assert chk.intrusive is True
    f = await chk.run(s)
    assert f and f.check == "INJECT-001"
    assert f.severity == "critical"
