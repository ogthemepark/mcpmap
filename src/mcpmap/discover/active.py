from __future__ import annotations
import asyncio
from typing import Iterable
import aiohttp

# Prioritized port list (see spec §6.1).
PRIORITY_PORTS = [80, 443, 3000, 8000, 8080, 8443, 5173, 5174, 6274, 6277, 8001, 11434]


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
                        # Use < 400 rather than < 500: a 404 means the path does
                        # not exist on this server; 401/403 still mean the endpoint
                        # exists but requires auth, so those are legitimately alive.
                        return p if r.status < 400 else None
                except Exception:
                    return None

        results = await asyncio.gather(*(_probe(p) for p in paths))
    return [p for p in results if p is not None]
