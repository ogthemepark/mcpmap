from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-AUTH-ORIGIN-MISVALIDATED")

EVIL_ORIGIN = "https://evil.example"


class Auth003OriginValidation(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                # Probe 1: no Origin header. Open servers return 2xx with a result body →
                # AUTH-001 territory, not AUTH-003. Require '"result"' in the body so that
                # servers using HTTP 200 + JSONRPC error body for enforcement aren't bypassed.
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    no_origin_status = r.status
                    no_origin_text = await r.text()
                if 200 <= no_origin_status < 300 and '"result"' in no_origin_text:
                    return None  # server doesn't care about Origin (or about anything) — not AUTH-003

                # Probe 2: evil Origin. If this succeeds where no-Origin failed, the server
                # has Origin-aware logic but accepts attacker-controlled values.
                headers = {"Origin": EVIL_ORIGIN, "Accept": "application/json, text/event-stream"}
                async with s.post(server.url, json=payload, headers=headers) as r:
                    if 200 <= r.status < 300:
                        text = await r.text()
                        return Finding(
                            check=self.id,
                            aliases=list(_REC.legacy_aliases),
                            severity=Severity(_REC.default_severity),
                            confidence=Confidence(_REC.default_confidence),
                            cwe=_REC.cwe or None,
                            cvss=5.4,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            title=_REC.title,
                            evidence=Evidence(
                                response_status=r.status,
                                response_excerpt=text[:256],
                                artifacts={
                                    "no_origin_status": no_origin_status,
                                    "no_origin_response_excerpt": no_origin_text[:256],
                                    "sent_origin": EVIL_ORIGIN,
                                    "evil_origin_status": r.status,
                                },
                            ),
                            repro=f"curl -X POST {server.url} -H 'Origin: {EVIL_ORIGIN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                        )
        except aiohttp.ClientError:
            return None
        return None
