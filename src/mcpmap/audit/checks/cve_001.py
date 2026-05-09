from __future__ import annotations
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck
from mcpmap.fingerprint.cves import cves_for


class Cve001VersionMatch(BaseCheck):
    id = "CVE-001"
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
            severity=Severity(m.severity),
            cvss=m.cvss,
            cve=m.cve,
            title=m.title,
            evidence={"fingerprint_id": server.fingerprint_id, "version": server.server_info.version, "all_matches": [c.cve for c in matches]},
            repro=f"See: {m.source}",
            remediation=(
                f"Upgrade {server.fingerprint_id} to a patched version. See the linked "
                f"advisory for affected versions and fix details."
            ),
        )
