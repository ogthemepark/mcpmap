from __future__ import annotations
import asyncio
from mcpmap.models import Server, Finding
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.correlate import rollup


async def _throttled(coro_factory, sem: asyncio.Semaphore, min_interval: float, last_ts: list[float]):
    async with sem:
        now = asyncio.get_running_loop().time()
        wait = max(0.0, last_ts[0] + min_interval - now)
        if wait:
            await asyncio.sleep(wait)
        last_ts[0] = asyncio.get_running_loop().time()
        return await coro_factory()


async def run_checks(
    server: Server,
    checks: list[BaseCheck],
    passive: bool = False,
    rate_rps: int | None = None,
) -> list[Finding]:
    """Run all checks against a server. Skip intrusive ones if passive=True."""
    enabled = [c for c in checks if not (passive and c.intrusive)]
    if not rate_rps or rate_rps <= 0:
        results = await asyncio.gather(*(c.run(server) for c in enabled), return_exceptions=True)
    else:
        sem = asyncio.Semaphore(1)
        min_interval = 1.0 / rate_rps
        last_ts = [0.0]
        results = await asyncio.gather(
            *(_throttled(lambda c=c: c.run(server), sem, min_interval, last_ts) for c in enabled),
            return_exceptions=True,
        )
    findings = [f for f in results if isinstance(f, Finding)]
    return rollup(findings)
