import pytest
from mcpmap.models import Server, Severity, Finding
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.runner import run_checks


class _AlwaysFires(BaseCheck):
    id = "TEST-001"
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        return Finding(check=self.id, severity=Severity.LOW, title="hi")


class _Intrusive(BaseCheck):
    id = "INTR-001"
    intrusive = True

    async def run(self, server: Server) -> Finding | None:
        return Finding(check=self.id, severity=Severity.HIGH, title="boom")


@pytest.mark.asyncio
async def test_runner_executes_all_checks_default():
    s = Server(url="http://t/mcp")
    findings = await run_checks(s, [_AlwaysFires(), _Intrusive()], passive=False)
    assert {f.check for f in findings} == {"TEST-001", "INTR-001"}


@pytest.mark.asyncio
async def test_runner_skips_intrusive_in_passive_mode():
    s = Server(url="http://t/mcp")
    findings = await run_checks(s, [_AlwaysFires(), _Intrusive()], passive=True)
    assert {f.check for f in findings} == {"TEST-001"}
