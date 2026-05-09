from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck


# A deliberately-bogus opaque token — must look like a JWT/Bearer to the server but match no real audience.
DECOY_TOKEN = "Bearer mcpmap.decoy.unrelated-audience.AAAAAAAA"


class Auth002AudienceBinding(BaseCheck):
    id = "AUTH-002"
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        headers = {"Authorization": DECOY_TOKEN, "Accept": "application/json, text/event-stream"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                async with s.post(server.url, json=payload, headers=headers) as r:
                    text = await r.text()
                    if r.status == 200 and '"result"' in text:
                        return Finding(
                            check=self.id,
                            severity=Severity.HIGH,
                            cvss=8.1,
                            title="Token audience not validated (RFC 8707 violation)",
                            evidence={"sent_token": DECOY_TOKEN, "status": r.status, "response_excerpt": text[:512]},
                            repro=f"curl -X POST {server.url} -H 'Authorization: {DECOY_TOKEN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                        )
        except aiohttp.ClientError:
            return None
        return None
