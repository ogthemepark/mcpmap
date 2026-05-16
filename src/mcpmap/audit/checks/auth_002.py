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
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                # Probe 1: no token. If this succeeds, the server has no auth at all —
                # AUTH-001's territory, not ours. Stay silent.
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    no_tok_status = r.status
                    no_tok_text = await r.text()
                if no_tok_status == 200 and '"result"' in no_tok_text:
                    return None  # no auth — let AUTH-001 own this finding

                # Probe 2: bogus token. If this succeeds, the server requires a token
                # but doesn't validate audience.
                headers = {"Authorization": DECOY_TOKEN, "Accept": "application/json, text/event-stream"}
                async with s.post(server.url, json=payload, headers=headers) as r:
                    if r.status == 200:
                        text = await r.text()
                        if '"result"' in text:
                            return Finding(
                                check=self.id,
                                severity=Severity.HIGH,
                                cvss=8.1,
                                title="Token audience not validated (RFC 8707 violation)",
                                evidence={
                                    "no_token_status": no_tok_status,
                                    "no_token_response_excerpt": no_tok_text[:256],
                                    "bogus_token": DECOY_TOKEN,
                                    "bogus_token_status": r.status,
                                    "response_excerpt": text[:512],
                                },
                                repro=f"curl -X POST {server.url} -H 'Authorization: {DECOY_TOKEN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                                remediation=(
                                    "Validate the audience (`aud`) claim of every bearer token against this "
                                    "server's canonical resource URI (RFC 8707). Reject tokens minted for "
                                    "other audiences even if signed by the same IdP."
                                ),
                            )
        except aiohttp.ClientError:
            return None
        return None
