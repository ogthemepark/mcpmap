from __future__ import annotations
import asyncio
from mcpmap.models import Server, Finding
from mcpmap.audit.base import BaseCheck


async def run_checks(
    server: Server,
    checks: list[BaseCheck],
    passive: bool = False,
) -> list[Finding]:
    """Run all checks against a server. Skip intrusive ones if passive=True."""
    enabled = [c for c in checks if not (passive and c.intrusive)]
    results = await asyncio.gather(*(c.run(server) for c in enabled), return_exceptions=True)
    return [f for f in results if isinstance(f, Finding)]
