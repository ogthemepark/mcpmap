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


def _parse_sse_result(text: str, transport: str) -> dict | None:
    """Extract the first valid JSON-RPC 2.0 result from SSE text, tagging transport."""
    import json as _j
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                payload = _j.loads(line[5:].strip())
                if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                    result = payload.get("result")
                    if isinstance(result, dict):
                        result["_mcpmap_transport"] = transport
                    return result
            except Exception:
                continue
    return None


async def _get_sse_handshake(url: str, timeout: float) -> dict | None:
    """Fallback: try GET on `url` expecting a legacy http+sse stream that includes
    the initialize result automatically (no POST needed).
    """
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(
            timeout=timeout_cfg,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.get(
                url, headers={"Accept": "text/event-stream"}
            ) as r:
                if r.status >= 400:
                    return None
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" not in ctype:
                    return None
                body = await r.content.read(8192)
                text = body.decode("utf-8", errors="ignore")
                return _parse_sse_result(text, "http+sse")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def initialize(
    url: str,
    timeout: float = 5.0,
    extra_headers: dict | None = None,
) -> dict | None:
    """POST a real MCP initialize. Return result dict on confirmed MCP, else None.

    Accepts JSON responses, POST-SSE responses (Content-Type: text/event-stream),
    and GET-only legacy http+sse streams (where POST returns 405).
    The returned dict always carries a synthetic '_mcpmap_transport' key with
    either 'streamable-http' or 'http+sse'. Callers must pop() it before
    serializing to avoid leaking it into stored scan data.
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
                # Legacy http+sse: POST returns 405 → fall back to GET SSE stream.
                if r.status == 405:
                    return await _get_sse_handshake(url, timeout)

                ctype = r.headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    body = await r.content.read(8192)
                    text = body.decode("utf-8", errors="ignore")
                    # SSE frames look like: "event: message\ndata: {json}\n\n"
                    return _parse_sse_result(text, "http+sse")

                try:
                    payload = await r.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    return None
                if not isinstance(payload, dict):
                    return None
                if payload.get("jsonrpc") == "2.0" and "result" in payload:
                    result = payload["result"]
                    if isinstance(result, dict):
                        result["_mcpmap_transport"] = "streamable-http"
                    return result
                return None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None
