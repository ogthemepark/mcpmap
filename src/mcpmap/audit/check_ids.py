from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckRec:
    canonical_id: str
    legacy_aliases: tuple[str, ...]
    title: str
    cwe: str
    default_severity: str
    default_confidence: str


CHECKS: tuple[CheckRec, ...] = (
    CheckRec("MCP-AUTH-UNAUTH-LIST",         ("AUTH-001",),      "tools/list available without authentication",         "CWE-306",  "high",     "high"),
    CheckRec("MCP-AUTH-AUDIENCE-MISBOUND",   ("AUTH-002",),      "Token audience not validated (RFC 8707)",             "CWE-1220", "high",     "high"),
    CheckRec("MCP-AUTH-ORIGIN-MISVALIDATED", ("AUTH-003",),      "Origin header not validated (DNS-rebinding risk)",    "CWE-346",  "medium",   "medium"),
    CheckRec("MCP-TPA-DESC-INJECT",          ("POISON-001",),    "Tool description contains prompt-injection markers",  "CWE-77",   "high",     "medium"),
    CheckRec("MCP-TPA-UNICODE-SMUGGLE",      ("POISON-002",),    "Tool description contains hidden Unicode characters", "CWE-176",  "high",     "high"),
    CheckRec("MCP-TOOL-CMD-INJECT",          ("INJECT-001",),    "Command injection via tool argument (canary echo)",   "CWE-78",   "critical", "high"),
    CheckRec("MCP-RES-SSRF",                 ("SSRF-001",),      "resources/read accepts dangerous URI schemes",        "CWE-918",  "high",     "medium"),
    CheckRec("MCP-TRANSPORT-LEGACY-SSE",     ("TRANSPORT-001",), "Legacy http+sse transport (deprecated)",              "CWE-1188", "medium",   "high"),
    CheckRec("MCP-META-HONEYPOT",            ("HONEYPOT-001",),  "Likely honeypot — suppress in operator triage",       "",         "info",     "low"),
    CheckRec("MCP-CVE-VERSION-MATCH",        ("CVE-001",),       "Known CVE matched via fingerprint + version",         "",         "high",     "high"),
)

_BY_CANON = {r.canonical_id: r for r in CHECKS}
_LEGACY = {alias: r.canonical_id for r in CHECKS for alias in r.legacy_aliases}


def by_id(canonical_id: str) -> CheckRec:
    return _BY_CANON[canonical_id]


def legacy_to_canonical(legacy_id: str) -> str | None:
    return _LEGACY.get(legacy_id)


def canonical_to_legacy(canonical_id: str) -> tuple[str, ...]:
    return _BY_CANON[canonical_id].legacy_aliases if canonical_id in _BY_CANON else ()
