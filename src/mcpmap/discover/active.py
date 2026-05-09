from __future__ import annotations
import asyncio
from typing import Iterable

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
