from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck


class Auth001UnauthToolsList(BaseCheck):
    id = "AUTH-001"
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
                            severity=Severity.HIGH,
                            cvss=7.5,
                            title="tools/list available without authentication",
                            evidence={"request": payload, "status": r.status, "response_excerpt": text[:512]},
                            repro=f"curl -X POST {server.url} -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                            remediation=(
                                "Require OAuth 2.1 (PKCE) on tools/list and resources/list per the MCP "
                                "auth spec. Reject unauthenticated POSTs with HTTP 401. Audit any client "
                                "library that bypasses this header by default."
                            ),
                        )
        except aiohttp.ClientError:
            return None
        return None
