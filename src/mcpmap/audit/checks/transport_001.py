from __future__ import annotations
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-TRANSPORT-LEGACY-SSE")


class Transport001LegacySse(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        if server.transport == "http+sse":
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
                    artifacts={"transport": server.transport, "url": server.url},
                ),
                repro="Confirm with: curl -s -H 'Accept: text/event-stream' " + server.url,
            )
        return None
