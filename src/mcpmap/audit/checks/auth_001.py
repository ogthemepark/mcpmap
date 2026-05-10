from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-AUTH-UNAUTH-LIST")


class Auth001UnauthToolsList(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    text = await r.text()
                    if r.status == 200 and '"result"' in text and '"tools"' in text:
                        return Finding(
                            check=self.id,
                            aliases=list(_REC.legacy_aliases),
                            severity=Severity(_REC.default_severity),
                            confidence=Confidence(_REC.default_confidence),
                            cwe=_REC.cwe or None,
                            cvss=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            title=_REC.title,
                            evidence=Evidence(
                                request=payload,
                                response_status=r.status,
                                response_excerpt=text[:512],
                            ),
                            repro=f"curl -X POST {server.url} -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                        )
        except aiohttp.ClientError:
            return None
        return None
