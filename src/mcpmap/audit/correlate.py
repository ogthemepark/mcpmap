from __future__ import annotations
from mcpmap.models import Finding


# Each entry: child_check_id -> root_check_id. If both present in a single server's
# findings, the child is annotated with related_to=root.
_ROLLUP_RULES: dict[str, str] = {
    "MCP-AUTH-AUDIENCE-MISBOUND":   "MCP-AUTH-UNAUTH-LIST",
    "MCP-AUTH-ORIGIN-MISVALIDATED": "MCP-AUTH-UNAUTH-LIST",
}


def rollup(findings: list[Finding]) -> list[Finding]:
    """Annotate dependent findings with related_to pointing at their root finding.

    Does NOT remove findings — only stamps related_to. Reports decide how to render
    confirmations vs. root findings. Idempotent: calling twice is safe.
    """
    present = {f.check for f in findings}
    out: list[Finding] = []
    for f in findings:
        root = _ROLLUP_RULES.get(f.check)
        if root and root in present:
            out.append(f.model_copy(update={"related_to": root}))
        else:
            out.append(f)
    return out
