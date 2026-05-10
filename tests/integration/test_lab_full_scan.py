import os
import pytest
from mcpmap.discover.active import active_discover
from mcpmap.discover.handshake import initialize
from mcpmap.fingerprint.db import match_fingerprint
from mcpmap.models import Server, ServerInfo, Tool
from mcpmap.audit.runner import run_checks
from mcpmap.audit.checks.auth_001 import Auth001UnauthToolsList
from mcpmap.audit.checks.auth_002 import Auth002AudienceBinding
from mcpmap.audit.checks.auth_003 import Auth003OriginValidation
from mcpmap.audit.checks.poison_001 import Poison001ToolDescriptionRegex
from mcpmap.audit.checks.poison_002 import Poison002UnicodeTags
from mcpmap.audit.checks.inject_001 import Inject001CanaryEcho
from mcpmap.audit.checks.ssrf_001 import Ssrf001ResourcesRead
from mcpmap.audit.checks.transport_001 import Transport001LegacySse
from mcpmap.audit.checks.honeypot_001 import Honeypot001
from mcpmap.audit.checks.cve_001 import Cve001VersionMatch


pytestmark = pytest.mark.skipif(
    os.environ.get("MCPMAP_LAB", "off") != "on",
    reason="set MCPMAP_LAB=on after `docker compose up` in testlab/",
)

ALL_CHECKS = [
    Auth001UnauthToolsList(), Auth002AudienceBinding(), Auth003OriginValidation(),
    Poison001ToolDescriptionRegex(), Poison002UnicodeTags(),
    Inject001CanaryEcho(), Ssrf001ResourcesRead(),
    Transport001LegacySse(), Honeypot001(), Cve001VersionMatch(),
]


@pytest.mark.asyncio
async def test_lab_discovers_all_ten_servers():
    targets = await active_discover("127.0.0.1", ports=list(range(8001, 8011)))
    assert len(targets) == 10, f"expected all 10 lab servers, got {len(targets)}: {[(t.port, t.path_hint) for t in targets]}"


async def _enrich(url: str) -> Server:
    res = await initialize(url)
    assert res, f"no init: {url}"
    info = ServerInfo(**(res.get("serverInfo") or {}))
    s = Server(url=url, server_info=info, capabilities=res.get("capabilities", {}), protocol_version=res.get("protocolVersion"))
    s.fingerprint_id = match_fingerprint(info, port=int(url.rsplit(':', 1)[1].split('/')[0]))
    import aiohttp
    async with aiohttp.ClientSession() as sess:
        async with sess.post(url, json={"jsonrpc":"2.0","id":1,"method":"tools/list"}) as r:
            try:
                data = await r.json(content_type=None)
                s.tools = [Tool(**t) for t in data.get("result", {}).get("tools", [])]
            except Exception:
                pass
    return s


@pytest.mark.asyncio
async def test_each_check_fires_at_least_once():
    fired: set[str] = set()
    for port in range(8001, 8011):
        url = f"http://127.0.0.1:{port}/mcp"
        try:
            srv = await _enrich(url)
        except AssertionError:
            continue
        if port == 8008:
            srv.transport = "http+sse"
        findings = await run_checks(srv, ALL_CHECKS, passive=False)
        for f in findings:
            fired.add(f.check)

    expected = {"AUTH-001", "AUTH-002", "AUTH-003", "POISON-001", "POISON-002", "INJECT-001", "SSRF-001", "TRANSPORT-001", "HONEYPOT-001", "CVE-001"}
    assert expected.issubset(fired), f"missing: {expected - fired}"
