from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-AUTH-AUDIENCE-MISBOUND")

# A deliberately-bogus opaque token — must look like a JWT/Bearer to the server but match no real audience.
DECOY_TOKEN = "Bearer mcpmap.decoy.unrelated-audience.AAAAAAAA"


class Auth002AudienceBinding(BaseCheck):
    id = _REC.canonical_id
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
                                aliases=list(_REC.legacy_aliases),
                                severity=Severity(_REC.default_severity),
                                confidence=Confidence(_REC.default_confidence),
                                cwe=_REC.cwe or None,
                                cvss=8.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                                title=_REC.title,
                                evidence=Evidence(
                                    response_status=r.status,
                                    response_excerpt=text[:512],
                                    artifacts={
                                        "no_token_status": no_tok_status,
                                        "no_token_response_excerpt": no_tok_text[:256],
                                        "bogus_token": DECOY_TOKEN,
                                        "bogus_token_status": r.status,
                                    },
                                ),
                                repro=f"curl -X POST {server.url} -H 'Authorization: {DECOY_TOKEN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                            )
        except aiohttp.ClientError:
            return None
        return None
