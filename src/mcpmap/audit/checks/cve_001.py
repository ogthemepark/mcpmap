from __future__ import annotations
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id
from mcpmap.fingerprint.cves import cves_for

_REC = by_id("MCP-CVE-VERSION-MATCH")


class Cve001VersionMatch(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        if not server.fingerprint_id or not server.server_info.version:
            return None
        matches = cves_for(server.fingerprint_id, server.server_info.version)
        if not matches:
            return None
        m = max(matches, key=lambda c: c.cvss)
        return Finding(
            check=self.id,
            aliases=list(_REC.legacy_aliases),
            severity=Severity(m.severity),
            confidence=Confidence(_REC.default_confidence),
            cwe=_REC.cwe or None,
            cvss=m.cvss,
            cve=m.cve,
            title=m.title,
            evidence=Evidence(
                artifacts={
                    "fingerprint_id": server.fingerprint_id,
                    "version": server.server_info.version,
                    "all_matches": [c.cve for c in matches],
                },
            ),
            repro=f"See: {m.source}",
        )
