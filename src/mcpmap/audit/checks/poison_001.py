from __future__ import annotations
import re
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck

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
    id = "POISON-001"
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
            severity=Severity.HIGH,
            cvss=8.0,
            title="Tool description contains prompt-injection / TPA patterns",
            evidence={"hits": hits},
            repro="Inspect each flagged tool's `description` returned from tools/list.",
            remediation=(
                "Strip / reject prompt-injection markup (e.g., <IMPORTANT>, "
                "system/assistant tags, references to ~/.ssh, ~/.aws, mcp.json) from "
                "tool descriptions before publishing. Treat tool registration as "
                "untrusted input and apply the same hygiene as user-generated content."
            ),
        )
