from __future__ import annotations
import unicodedata
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-TPA-UNICODE-SMUGGLE")

_HIDDEN_RANGES = [
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
]


def _has_hidden(text: str) -> list[str]:
    found: list[str] = []
    for ch in text:
        cp = ord(ch)
        for lo, hi in _HIDDEN_RANGES:
            if lo <= cp <= hi:
                found.append(f"U+{cp:04X}")
                break
    return found


class Poison002UnicodeTags(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        hits: list[dict] = []
        for tool in server.tools:
            desc = tool.description or ""
            hidden = _has_hidden(desc)
            normalized = unicodedata.normalize("NFKC", desc)
            if hidden or len(normalized) != len(desc):
                hits.append({"tool": tool.name, "hidden_codepoints": hidden, "len_raw": len(desc), "len_nfkc": len(normalized)})
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
            repro="Inspect raw bytes of each flagged tool's description; render via xxd or hex viewer.",
        )
