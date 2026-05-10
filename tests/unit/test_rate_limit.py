import asyncio
import time
import pytest
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.runner import run_checks


class _Slow(BaseCheck):
    id = "TEST"
    intrusive = False
    async def run(self, server):
        await asyncio.sleep(0.05)
        return Finding(check=self.id, severity=Severity.LOW, title="t")


@pytest.mark.asyncio
async def test_rate_limit_caps_concurrency():
    s = Server(url="http://x/mcp")
    checks = [_Slow() for _ in range(10)]
    start = time.perf_counter()
    await run_checks(s, checks, passive=False, rate_rps=2)
    elapsed = time.perf_counter() - start
    # 10 checks at 2/s with 50ms each → must take >= ~5s, well above the 0.5s an unthrottled run takes
    assert elapsed >= 4.0, f"expected throttling, took {elapsed:.2f}s"
