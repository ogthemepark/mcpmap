from __future__ import annotations
import re
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-TPA-DESC-INJECT")

POISON_PATTERNS = [
    r"<\s*IMPORTANT\s*>",
    r"</?\s*system\s*>",
    r"</?\s*assistant\s*>",
    r"~/\.ssh",
    r"~/\.aws",
    r"id_rsa\b",
    r"BEGIN\s+(?:RSA|OPENSSH)",
    r"mcp\.json",
    r"before\s+using\s+this\s+tool",
    r"ignore\s+previous",
    r"Bearer\s+[A-Za-z0-9._-]{20,}",
    r"!\[.*?\]\(http",
]
_compiled = [re.compile(p, re.IGNORECASE) for p in POISON_PATTERNS]


class Poison001ToolDescriptionRegex(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        hits: list[dict] = []
        for tool in server.tools:
            for rx in _compiled:
                m = rx.search(tool.description or "")
                if m:
                    hits.append({"tool": tool.name, "pattern": rx.pattern, "match": m.group(0)})
        if not hits:
            return None
        return Finding(
            check=self.id,
            aliases=list(_REC.legacy_aliases),
            severity=Severity(_REC.default_severity),
            confidence=Confidence(_REC.default_confidence),
            cwe=_REC.cwe or None,
            cvss=8.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            title=_REC.title,
            evidence=Evidence(
                artifacts={"hits": hits},
            ),
            repro="Inspect each flagged tool's `description` returned from tools/list.",
        )
