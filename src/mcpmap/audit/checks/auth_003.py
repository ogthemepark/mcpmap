from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck

EVIL_ORIGIN = "https://evil.example"


class Auth003OriginValidation(BaseCheck):
    id = "AUTH-003"
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                # Probe 1: no Origin header. Open servers return 2xx → AUTH-001 territory.
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    no_origin_status = r.status
                if 200 <= no_origin_status < 300:
                    return None  # server doesn't care about Origin (or about anything) — not AUTH-003

                # Probe 2: evil Origin. If this succeeds where no-Origin failed, the server
                # has Origin-aware logic but accepts attacker-controlled values.
                headers = {"Origin": EVIL_ORIGIN, "Accept": "application/json, text/event-stream"}
                async with s.post(server.url, json=payload, headers=headers) as r:
                    if 200 <= r.status < 300:
                        text = await r.text()
                        return Finding(
                            check=self.id,
                            severity=Severity.MEDIUM,
                            cvss=5.4,
                            title="Origin header not validated (DNS-rebinding risk)",
                            evidence={
                                "no_origin_status": no_origin_status,
                                "sent_origin": EVIL_ORIGIN,
                                "evil_origin_status": r.status,
                                "response_excerpt": text[:256],
                            },
                            repro=f"curl -X POST {server.url} -H 'Origin: {EVIL_ORIGIN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                            remediation=(
                                "Validate the Origin header against an explicit allowlist before "
                                "accepting the request; for localhost-only servers, bind to 127.0.0.1 "
                                "(not 0.0.0.0) and require Origin to be 'http://localhost' or a known "
                                "client UI. Mitigates DNS-rebinding."
                            ),
                        )
        except aiohttp.ClientError:
            return None
        return None
