from __future__ import annotations
import asyncio
import uuid
import aiohttp

MCP_PROTOCOL_VERSION = "2025-11-25"


def _init_payload() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpmap", "version": "0.1.0"},
        },
    }


async def initialize(
    url: str,
    timeout: float = 5.0,
    extra_headers: dict | None = None,
) -> dict | None:
    """POST a real MCP initialize. Return result dict on confirmed MCP, else None.

    Accepts either JSON or SSE-wrapped JSON responses.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    if extra_headers:
        headers.update(extra_headers)

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, connector=connector) as session:
            async with session.post(url, json=_init_payload(), headers=headers) as r:
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    body = await r.content.read(8192)
                    text = body.decode("utf-8", errors="ignore")
                    # SSE frames look like: "event: message\ndata: {json}\n\n"
                    for line in text.splitlines():
                        if line.startswith("data:"):
                            try:
                                import json as _j
                                payload = _j.loads(line[5:].strip())
                                if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                                    return payload.get("result")
                            except Exception:
                                continue
                    return None

                try:
                    payload = await r.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    return None
                if not isinstance(payload, dict):
                    return None
                if payload.get("jsonrpc") == "2.0" and "result" in payload:
                    return payload["result"]
                return None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None
