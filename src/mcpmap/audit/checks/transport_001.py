from __future__ import annotations
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck


class Transport001LegacySse(BaseCheck):
    id = "TRANSPORT-001"
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        if server.transport == "http+sse":
            return Finding(
                check=self.id,
                severity=Severity.MEDIUM,
                cvss=5.4,
                title="Server speaks legacy HTTP+SSE (deprecated, DNS-rebinding-prone)",
                evidence={"transport": server.transport, "url": server.url},
                repro="Confirm with: curl -s -H 'Accept: text/event-stream' " + server.url,
            )
        return None
