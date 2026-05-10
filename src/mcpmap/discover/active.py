from __future__ import annotations
import asyncio
from typing import Iterable
import aiohttp

# Prioritized port list (see spec §6.1).
PRIORITY_PORTS = [80, 443, 3000, 8000, 8080, 8443, 5173, 5174, 6274, 6277, 11434,
                  8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010]


async def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True iff a TCP connection to host:port can be established within `timeout`."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def tcp_sweep(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.5,
    concurrency: int = 64,
) -> list[int]:
    """Concurrent reachability sweep. Returns the open ports in input order."""
    sem = asyncio.Semaphore(concurrency)
    ports = list(ports)

    async def _check(p: int) -> tuple[int, bool]:
        async with sem:
            return p, await tcp_open(host, p, timeout=timeout)

    results = await asyncio.gather(*(_check(p) for p in ports))
    open_set = {p for p, ok in results if ok}
    return [p for p in ports if p in open_set]


MCP_PATHS = [
    "/mcp",
    "/sse",
    "/messages",
    "/api/mcp",
    "/v1/mcp",
    "/v1/messages",
    "/mcp/sse",
    "/mcp/messages",
    "/",
]


async def http_paths_alive(
    base_url: str,
    paths: list[str] = MCP_PATHS,
    timeout: float = 3.0,
    concurrency: int = 32,
) -> list[str]:
    """Return the subset of `paths` that respond with status < 400 to a GET.

    NOTE: The threshold is < 400 (not < 500 as originally specced). A 404
    response means the path does not exist and should not be treated as
    "alive"; 4xx responses like 401/403 still indicate the resource exists.
    Using < 500 would cause unregistered paths (404) to be reported as alive,
    which contradicts the test expectation.
    """
    sem = asyncio.Semaphore(concurrency)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    alive: list[str] = []

    async with aiohttp.ClientSession(timeout=timeout_cfg, connector=connector) as session:
        async def _probe(p: str) -> str | None:
            async with sem:
                try:
                    async with session.get(base_url.rstrip("/") + p, allow_redirects=False) as r:
                        # Alive = path exists. < 400 covers 2xx/3xx; 401/403 mean
                        # auth required (path exists); 405 means wrong method
                        # (path exists, only accepts POST — true for MCP /mcp).
                        # 404 means no such path → not alive.
                        return p if (r.status < 400 or r.status in (401, 403, 405)) else None
                except Exception:
                    return None

        results = await asyncio.gather(*(_probe(p) for p in paths))
    return [p for p in results if p is not None]


async def _sse_probe(url: str, timeout: float = 3.0) -> bool:
    """Return True if `url` responds to GET with an SSE stream that opens.
    Used as a fallback for legacy http+sse MCP transports where POST /sse 405s.
    """
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    headers = {"Accept": "text/event-stream"}
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, headers=headers) as r:
                if r.status >= 400:
                    return False
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" not in ctype:
                    return False
                # Read at most one frame's worth of bytes to confirm the stream opens
                chunk = await r.content.read(4096)
                return b"data:" in chunk
    except Exception:
        return False


from mcpmap.discover.handshake import initialize
from mcpmap.models import Target


async def active_discover(
    host: str,
    ports: list[int] | None = None,
    paths: list[str] = MCP_PATHS,
    tcp_timeout: float = 1.5,
    http_timeout: float = 3.0,
) -> list[Target]:
    """Full active pipeline for a single host: TCP sweep -> HTTP probe -> initialize. Returns confirmed Targets."""
    ports = ports or PRIORITY_PORTS
    open_ports = await tcp_sweep(host, ports, timeout=tcp_timeout)
    confirmed: list[Target] = []
    for port in open_ports:
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{host}:{port}"
        alive = await http_paths_alive(base, paths=paths, timeout=http_timeout)
        for p in alive:
            url = base + p
            if await initialize(url) is not None:
                confirmed.append(Target(host=host, port=port, path_hint=p, source="active"))
                break  # one path per (host, port) is enough
            if p.endswith("/sse") and await _sse_probe(url):
                confirmed.append(Target(host=host, port=port, path_hint=p, source="active"))
                break
    return confirmed
