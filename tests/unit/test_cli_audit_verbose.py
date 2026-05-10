"""Smoke test for `audit -v` against an in-process aiohttp lab server."""
import asyncio
import pytest
from aiohttp import web
from typer.testing import CliRunner
from mcpmap.cli import app

async def _noauth_handler(request):
    body = await request.json()
    rid = body.get("id", 1)
    m = body.get("method")
    if m == "initialize":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-noauth", "version": "0.0.1"},
        }})
    if m == "tools/list":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "tools": [{"name": "echo", "description": "Echoes input.",
                       "inputSchema": {"type": "object"}}]
        }})
    return web.json_response({"jsonrpc": "2.0", "id": rid,
                              "error": {"code": -32601}})


@pytest.fixture
async def noauth(aiohttp_server):
    app_a = web.Application()
    app_a.router.add_post("/mcp", _noauth_handler)
    return await aiohttp_server(app_a)


@pytest.mark.asyncio
async def test_audit_verbose_shows_remediation(noauth):
    runner = CliRunner()
    url = f"http://{noauth.host}:{noauth.port}/mcp"
    # Run invoke in a thread executor so the event loop stays free to serve
    # the aiohttp test server while the CLI command makes HTTP requests.
    loop = asyncio.get_running_loop()
    r = await asyncio.wait_for(
        loop.run_in_executor(None, lambda: runner.invoke(app, ["audit", url, "--verbose"])),
        timeout=30,
    )
    assert r.exit_code == 0, r.output
    assert "AUTH-001" in r.output
    assert "Remediation" in r.output or "remediation" in r.output.lower()
    assert "OAuth" in r.output


@pytest.mark.asyncio
async def test_audit_quiet_omits_remediation(noauth):
    runner = CliRunner()
    url = f"http://{noauth.host}:{noauth.port}/mcp"
    loop = asyncio.get_running_loop()
    r = await asyncio.wait_for(
        loop.run_in_executor(None, lambda: runner.invoke(app, ["audit", url])),
        timeout=30,
    )
    assert r.exit_code == 0, r.output
    assert "AUTH-001" in r.output
    assert "OAuth" not in r.output
