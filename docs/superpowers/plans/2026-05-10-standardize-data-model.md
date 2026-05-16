# Standardize the Data Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **PRE-REQUISITE:** `2026-05-10-stabilize-and-fix-lies.md` should land first. This plan assumes the integration suite is green and the broken checks are fixed.

**Goal:** Make `mcpmap` look and behave like a professional security scanner. Externalize remediations (no LLM, no hand-written strings in check code), give findings a typed Evidence object, add CVSS vector strings + CWE mapping + confidence scores, correlate findings (one root + N confirmations instead of three duplicate criticals), wire `--rate` into actual rate-limiting, and rename the check IDs to legible domain-specific identifiers with deprecation aliases so existing `scan.json` files still validate.

**Architecture:** Pure refactor. New types in `models.py`, new data file in `data/remediations.yaml`, new helper module `audit/cvss.py` for vector parsing/scoring, new module `audit/correlate.py` for finding rollup. Existing checks change only their `Finding(...)` constructor calls and remediation strings (which move out of code into YAML). Backwards-compat: legacy IDs (`AUTH-001`) accepted as aliases of new IDs (`MCP-AUTH-UNAUTH-LIST`) in deserializers and report rendering.

**Tech Stack:** Same as Plan 1. Add `cvss>=3.0` PyPI package for vector parsing (or implement a 60-line parser in `audit/cvss.py` — recommend the package, it's a single-file dep with zero transitives).

**Pre-flight:**
```bash
cd /Users/lalithmacharla/projects/brainstorming/mcpmap
source .venv/bin/activate
pytest tests/unit -q && MCPMAP_LAB=on pytest tests/integration -v
# All green from Plan 1. If not, finish Plan 1 first.
pip install cvss
```

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/mcpmap/models.py` | Pydantic models for the wire format | Modify: add `Evidence`, `CvssVector`, `Confidence` enum, `Finding.confidence`, `Finding.cwe`, `Finding.aliases`, `Finding.related_to` |
| `src/mcpmap/audit/cvss.py` | CVSS 3.1 vector → score helper | Create: thin wrapper over `cvss` package; constants for the 10 finding archetypes |
| `src/mcpmap/audit/check_ids.py` | Canonical check ID registry + alias map | Create: source-of-truth for new IDs, legacy aliases, CWE mappings, severity defaults |
| `src/mcpmap/audit/correlate.py` | Finding deduplication & rollup | Create: collapse `MCP-AUTH-UNAUTH-LIST` + downstream noise into a root finding |
| `src/mcpmap/audit/remediations.py` | Load + lookup `data/remediations.yaml` | Create: cached load, lookup by check ID |
| `data/remediations.yaml` | Versioned remediation copy + citations | Create: one entry per check ID with `summary`, `references[]`, `cwe`, `spec_link` |
| `src/mcpmap/audit/checks/*.py` | Individual checks | Modify (all 10): use new IDs, drop inline remediations (let renderer fill from YAML), set `confidence`, set `cwe`, use `cvss.score_for(...)` |
| `src/mcpmap/audit/runner.py` | Check orchestration | Modify: add rate-limiting via `asyncio.Semaphore`, call `correlate.rollup()` before returning |
| `src/mcpmap/pipeline.py` | Top-level scan orchestration | Modify: pass `rate_rps` to runner; promote `_enrich_target` → public `enrich_target` |
| `src/mcpmap/cli.py` | CLI entry | Modify: import `enrich_target` (no underscore); ensure `--rate` is plumbed |
| `src/mcpmap/report/markdown_out.py` | Markdown report | Modify: render remediation from YAML lookup; show new IDs with legacy in parens |
| `src/mcpmap/report/html_out.py` + template | HTML report | Modify: same as markdown |
| `src/mcpmap/report/poc_out.py` | Per-finding PoC writeup | Modify: include CWE, CVSS vector, references[] from YAML |
| `tests/unit/test_models.py` | Model schema | Modify: tests for new fields, alias acceptance |
| `tests/unit/test_correlate.py` | Correlation logic | Create |
| `tests/unit/test_remediations.py` | YAML loader | Create |
| `tests/unit/test_check_*.py` (all 10) | Per-check tests | Modify: assert new ID; assert legacy ID still readable from `Finding.aliases` |
| `tests/unit/test_rate_limit.py` | Rate-limit enforcement | Create |

---

## Task 1: Add typed Evidence, Confidence, CWE, CVSS-vector fields to Finding

**Files:**
- Modify: `src/mcpmap/models.py`
- Modify: `tests/unit/test_models.py`

- [ ] **Step 1: Write failing tests for the new fields**

Append to `tests/unit/test_models.py`:

```python
from mcpmap.models import Finding, Severity, Confidence, Evidence


def test_finding_accepts_confidence_cwe_and_vector():
    f = Finding(
        check="MCP-AUTH-UNAUTH-LIST",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cvss=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-306",
        title="x",
    )
    assert f.confidence is Confidence.HIGH
    assert f.cwe == "CWE-306"
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.aliases == []
    assert f.related_to is None


def test_finding_evidence_is_typed():
    e = Evidence(request={"a": 1}, response_excerpt="ok", artifacts={"k": "v"})
    f = Finding(check="X", severity=Severity.LOW, title="t", evidence=e)
    assert f.evidence.request == {"a": 1}
    # Backwards-compat: still accepts a plain dict for evidence
    f2 = Finding(check="X", severity=Severity.LOW, title="t", evidence={"foo": "bar"})
    assert f2.evidence.artifacts == {"foo": "bar"}
```

- [ ] **Step 2: Run; expect FAIL**

```bash
pytest tests/unit/test_models.py -v
```

- [ ] **Step 3: Implement the new models**

In `src/mcpmap/models.py`, add after the `Severity` enum:

```python
class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Evidence(BaseModel):
    """Typed evidence container. All fields optional. Use `artifacts` for ad-hoc data
    that doesn't fit the named slots — keeps the wire format introspectable while
    allowing checks to attach idiosyncratic detail."""
    request: dict[str, Any] | None = None
    response_status: int | None = None
    response_excerpt: str | None = None
    matched_patterns: list[str] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_legacy(cls, raw: dict[str, Any] | "Evidence" | None) -> "Evidence":
        if raw is None:
            return cls()
        if isinstance(raw, cls):
            return raw
        # Pull known keys into named slots; rest goes to artifacts.
        named = {k: raw.pop(k) for k in ("request", "response_status", "response_excerpt", "matched_patterns") if k in raw}
        return cls(**named, artifacts=raw)
```

Replace the `Finding` class:

```python
class Finding(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    check: str                                   # canonical check ID, e.g. MCP-AUTH-UNAUTH-LIST
    aliases: list[str] = Field(default_factory=list)  # e.g. ["AUTH-001"] for back-compat
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    title: str
    cvss: float | None = None
    cvss_vector: str | None = None              # full CVSS 3.1 vector string
    cve: str | None = None
    cwe: str | None = None                       # e.g. "CWE-306"
    evidence: Evidence = Field(default_factory=Evidence)
    repro: str = ""
    remediation: str | None = None              # set by renderer from data/remediations.yaml; checks leave None
    related_to: str | None = None               # check ID of the parent finding (set by correlator)

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v):
        return Evidence.from_legacy(v) if not isinstance(v, Evidence) else v
```

Add the import at the top: `from pydantic import BaseModel, ConfigDict, Field, field_validator`.

- [ ] **Step 4: Re-run; expect PASS**

```bash
pytest tests/unit/test_models.py -v && pytest tests/unit -q
```

Expected: new tests PASS, all existing tests PASS (legacy `Finding(evidence={...})` still works via `from_legacy`).

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/models.py tests/unit/test_models.py
git commit -m "feat(models): add Confidence, Evidence, cvss_vector, cwe, aliases, related_to to Finding

Lays the data-model foundation for: per-finding confidence ratings,
CWE mapping, CVSS 3.1 vector strings, finding correlation (related_to),
and check-ID renames with back-compat aliases. Existing dict-shaped
evidence still deserializes via Evidence.from_legacy()."
```

---

## Task 2: Build the canonical check-ID registry with legacy aliases

**Files:**
- Create: `src/mcpmap/audit/check_ids.py`
- Create: `tests/unit/test_check_ids.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_check_ids.py`:

```python
from mcpmap.audit.check_ids import CHECKS, by_id, legacy_to_canonical


def test_every_legacy_id_maps_to_canonical():
    legacy = ["AUTH-001", "AUTH-002", "AUTH-003", "POISON-001", "POISON-002",
              "INJECT-001", "SSRF-001", "TRANSPORT-001", "HONEYPOT-001", "CVE-001"]
    for old in legacy:
        canon = legacy_to_canonical(old)
        assert canon is not None, f"no canonical mapping for {old}"
        rec = by_id(canon)
        assert old in rec.legacy_aliases


def test_each_canonical_check_has_cwe_and_severity_default():
    for rec in CHECKS:
        assert rec.cwe.startswith("CWE-") or rec.cwe == ""  # CVE-001 has no CWE
        assert rec.default_severity in {"info", "low", "medium", "high", "critical"}
        assert rec.canonical_id.startswith("MCP-")
```

- [ ] **Step 2: Run; expect FAIL** (module doesn't exist)

```bash
pytest tests/unit/test_check_ids.py -v
```

- [ ] **Step 3: Implement the registry**

Create `src/mcpmap/audit/check_ids.py`:

```python
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CheckRec:
    canonical_id: str
    legacy_aliases: tuple[str, ...]
    title: str
    cwe: str
    default_severity: str
    default_confidence: str


CHECKS: tuple[CheckRec, ...] = (
    CheckRec("MCP-AUTH-UNAUTH-LIST",       ("AUTH-001",),     "tools/list available without authentication",        "CWE-306", "high",     "high"),
    CheckRec("MCP-AUTH-AUDIENCE-MISBOUND", ("AUTH-002",),     "Token audience not validated (RFC 8707)",            "CWE-1220", "high",    "high"),
    CheckRec("MCP-AUTH-ORIGIN-MISVALIDATED", ("AUTH-003",),   "Origin header not validated (DNS-rebinding risk)",   "CWE-346", "medium",  "medium"),
    CheckRec("MCP-TPA-DESC-INJECT",        ("POISON-001",),   "Tool description contains prompt-injection markers", "CWE-77",  "high",    "medium"),
    CheckRec("MCP-TPA-UNICODE-SMUGGLE",    ("POISON-002",),   "Tool description contains hidden Unicode characters","CWE-176", "high",    "high"),
    CheckRec("MCP-TOOL-CMD-INJECT",        ("INJECT-001",),   "Command injection via tool argument (canary echo)",  "CWE-78",  "critical","high"),
    CheckRec("MCP-RES-SSRF",               ("SSRF-001",),     "resources/read accepts dangerous URI schemes",       "CWE-918", "high",    "medium"),
    CheckRec("MCP-TRANSPORT-LEGACY-SSE",   ("TRANSPORT-001",),"Legacy http+sse transport (deprecated)",             "CWE-1188","medium",  "high"),
    CheckRec("MCP-META-HONEYPOT",          ("HONEYPOT-001",), "Likely honeypot — suppress in operator triage",      "",        "info",    "low"),
    CheckRec("MCP-CVE-VERSION-MATCH",      ("CVE-001",),      "Known CVE matched via fingerprint + version",        "",        "high",    "high"),
)

_BY_CANON = {r.canonical_id: r for r in CHECKS}
_LEGACY = {alias: r.canonical_id for r in CHECKS for alias in r.legacy_aliases}


def by_id(canonical_id: str) -> CheckRec:
    return _BY_CANON[canonical_id]


def legacy_to_canonical(legacy_id: str) -> str | None:
    return _LEGACY.get(legacy_id)


def canonical_to_legacy(canonical_id: str) -> tuple[str, ...]:
    return _BY_CANON[canonical_id].legacy_aliases if canonical_id in _BY_CANON else ()
```

- [ ] **Step 4: Re-run; expect PASS**

```bash
pytest tests/unit/test_check_ids.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/audit/check_ids.py tests/unit/test_check_ids.py
git commit -m "feat(audit): add canonical check-ID registry with legacy aliases and CWE mapping

Source of truth for all check identifiers. Existing AUTH-001 etc. are
preserved as legacy aliases on the new MCP-AUTH-UNAUTH-LIST etc."
```

---

## Task 3: Externalize remediations into data/remediations.yaml

**Files:**
- Create: `data/remediations.yaml`
- Create: `src/mcpmap/audit/remediations.py`
- Create: `tests/unit/test_remediations.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_remediations.py`:

```python
from mcpmap.audit.remediations import lookup, all_remediations
from mcpmap.audit.check_ids import CHECKS


def test_every_canonical_check_has_a_remediation_entry():
    for rec in CHECKS:
        rem = lookup(rec.canonical_id)
        assert rem is not None, f"missing remediation for {rec.canonical_id}"
        assert rem.summary
        assert isinstance(rem.references, list)


def test_lookup_accepts_legacy_id():
    rem = lookup("AUTH-001")
    assert rem is not None and rem.summary
```

- [ ] **Step 2: Run; expect FAIL**

```bash
pytest tests/unit/test_remediations.py -v
```

- [ ] **Step 3: Create the YAML**

Create `data/remediations.yaml`:

```yaml
# Curated remediation library. Each entry maps a canonical check ID to a short
# operator-facing summary + verifiable citations. Keep summaries to ~3 sentences;
# put detail in references. Do NOT auto-generate this file with an LLM.

MCP-AUTH-UNAUTH-LIST:
  summary: |
    Require OAuth 2.1 (PKCE) on tools/list and resources/list per the MCP authorization
    spec. Reject unauthenticated POSTs with HTTP 401. If exposing tools to unauthenticated
    users is intentional, document it explicitly so triage can suppress this finding.
  references:
    - https://modelcontextprotocol.io/specification/draft/basic/authorization
    - https://www.knostic.ai/blog/find-mcp-server-shodan
  cwe: CWE-306

MCP-AUTH-AUDIENCE-MISBOUND:
  summary: |
    Validate the audience (`aud`) claim of every bearer token against this server's
    canonical resource URI per RFC 8707. Reject tokens minted for a different audience
    even if signed by a trusted IdP. This is the spec-mandated mitigation for
    confused-deputy attacks across MCP servers sharing an IdP.
  references:
    - https://datatracker.ietf.org/doc/html/rfc8707
    - https://modelcontextprotocol.io/specification/draft/basic/authorization
  cwe: CWE-1220

MCP-AUTH-ORIGIN-MISVALIDATED:
  summary: |
    Validate the Origin header against an explicit allowlist before accepting requests.
    For localhost-only servers, bind to 127.0.0.1 (not 0.0.0.0) and require Origin to
    be 'http://localhost' or a known client UI. Mitigates DNS rebinding (the class that
    enabled the MCP Inspector RCE, CVE-2025-49596).
  references:
    - https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#security-warning
    - https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596
  cwe: CWE-346

MCP-TPA-DESC-INJECT:
  summary: |
    Treat tool descriptions as untrusted user input. Strip or reject prompt-injection
    markup (e.g., <IMPORTANT>, faux system/assistant tags, references to ~/.ssh,
    ~/.aws, mcp.json) before publishing. Apply the same hygiene you would to
    user-generated content rendered into an LLM prompt.
  references:
    - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    - https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
  cwe: CWE-77

MCP-TPA-UNICODE-SMUGGLE:
  summary: |
    Reject tool descriptions whose NFKC-normalized form differs in length from the
    raw form, and any text containing codepoints in U+200B–U+200F, U+202A–U+202E,
    U+2060–U+206F, U+FEFF, or U+E0000–U+E007F. These ranges are invisible to humans
    but tokenized by LLMs.
  references:
    - https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/
  cwe: CWE-176

MCP-TOOL-CMD-INJECT:
  summary: |
    Never pass tool arguments to a shell. Use list-form subprocess calls (shell=False
    with explicit argv). For path arguments, validate against an allowlist of expected
    directories and reject any input containing shell metacharacters (`;`, `$`, `\``,
    `|`, `&`, newline). Same defect as Framelink Figma (CVE-2025-53967), nginx-ui
    (CVE-2026-33032), gemini-mcp-tool (CVE-2026-0755).
  references:
    - https://www.endorlabs.com/learn/cve-2025-53967-remote-code-execution-in-framelink-figma-mcp-server
    - https://cwe.mitre.org/data/definitions/78.html
  cwe: CWE-78

MCP-RES-SSRF:
  summary: |
    Restrict resources/read URI schemes to a strict allowlist. For file://, constrain
    to specific directories the server is meant to expose. For http(s)://, block
    link-local (169.254.0.0/16), loopback, and cloud-metadata addresses. Resolve DNS
    once and verify the resolved IP is in the allowed set.
  references:
    - https://cwe.mitre.org/data/definitions/918.html
  cwe: CWE-918

MCP-TRANSPORT-LEGACY-SSE:
  summary: |
    Migrate from the deprecated http+sse transport to streamable-http per the MCP
    2025-11-25 spec. Legacy SSE lacks Origin validation in most SDK defaults and is
    DNS-rebinding-prone.
  references:
    - https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
  cwe: CWE-1188

MCP-META-HONEYPOT:
  summary: |
    Operator note: this is a honeypot indicator, not a vulnerability in your code.
    If this server is yours and the signal is a false positive, use distinct
    Mcp-Session-Id values per connection. If the server is not yours, treat any
    other findings on this URL as low-confidence.
  references:
    - https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities
  cwe: ""

MCP-CVE-VERSION-MATCH:
  summary: |
    Upgrade the affected component to a patched version. See the linked advisory in
    the finding for the exact affected range and fix details. Pin upstream
    dependencies and subscribe to the affected SDK's security advisories.
  references:
    - https://authzed.com/blog/timeline-mcp-breaches
  cwe: ""
```

- [ ] **Step 4: Implement the loader**

Create `src/mcpmap/audit/remediations.py`:

```python
from __future__ import annotations
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
import yaml
from mcpmap.audit.check_ids import legacy_to_canonical


@dataclass(frozen=True)
class Remediation:
    summary: str
    references: tuple[str, ...] = ()
    cwe: str = ""


_DEFAULT_PATH = Path(__file__).parent.parent.parent.parent / "data" / "remediations.yaml"


@lru_cache(maxsize=1)
def all_remediations(path: str | None = None) -> dict[str, Remediation]:
    p = Path(path) if path else _DEFAULT_PATH
    raw = yaml.safe_load(p.read_text()) or {}
    return {
        check_id: Remediation(
            summary=entry.get("summary", "").strip(),
            references=tuple(entry.get("references", [])),
            cwe=entry.get("cwe", ""),
        )
        for check_id, entry in raw.items()
    }


def lookup(check_id: str) -> Remediation | None:
    table = all_remediations()
    if check_id in table:
        return table[check_id]
    canon = legacy_to_canonical(check_id)
    return table.get(canon) if canon else None
```

- [ ] **Step 5: Re-run; expect PASS**

```bash
pytest tests/unit/test_remediations.py -v
```

- [ ] **Step 6: Commit**

```bash
git add data/remediations.yaml src/mcpmap/audit/remediations.py tests/unit/test_remediations.py
git commit -m "feat(audit): externalize remediations to data/remediations.yaml

Decouples remediation copy from check code so updates are doc-style PRs
with citations rather than code changes. Loader is cached and accepts
both canonical (MCP-AUTH-UNAUTH-LIST) and legacy (AUTH-001) IDs."
```

---

## Task 4: Migrate every check to canonical IDs + drop inline remediations

**Files:**
- Modify: each `src/mcpmap/audit/checks/*.py` (10 files)
- Modify: each `tests/unit/test_check_*.py` (already-passing tests)

- [ ] **Step 1: Write the failing meta-test**

Create `tests/unit/test_checks_use_canonical_ids.py`:

```python
import pytest
from mcpmap.audit.check_ids import CHECKS
from mcpmap.pipeline import all_checks


def test_every_check_uses_canonical_id_and_declares_legacy_alias():
    canonical_ids = {r.canonical_id for r in CHECKS}
    legacy_ids = {alias for r in CHECKS for alias in r.legacy_aliases}
    seen = set()
    for chk in all_checks():
        assert chk.id in canonical_ids, f"{chk.__class__.__name__} uses non-canonical id {chk.id}"
        seen.add(chk.id)
    assert seen == canonical_ids, f"missing checks: {canonical_ids - seen}"
```

- [ ] **Step 2: Run; expect FAIL**

```bash
pytest tests/unit/test_checks_use_canonical_ids.py -v
```

- [ ] **Step 3: Migrate each check**

Pattern for every check (illustrated for `auth_001.py`):

```python
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-AUTH-UNAUTH-LIST")


class Auth001UnauthToolsList(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        # ... existing probe logic, unchanged ...
        if matched:
            return Finding(
                check=self.id,
                aliases=list(_REC.legacy_aliases),
                severity=Severity(_REC.default_severity),
                confidence=Confidence(_REC.default_confidence),
                cwe=_REC.cwe,
                cvss=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                title=_REC.title,
                evidence=Evidence(
                    request=payload,
                    response_status=r.status,
                    response_excerpt=text[:512],
                ),
                repro=f"curl -X POST {server.url} -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                # remediation: REMOVED — renderer fills it from data/remediations.yaml
            )
```

Apply this transformation to **all 10 checks**. CVSS vectors per check:

| canonical_id | cvss | vector |
|---|---|---|
| MCP-AUTH-UNAUTH-LIST | 7.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| MCP-AUTH-AUDIENCE-MISBOUND | 8.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| MCP-AUTH-ORIGIN-MISVALIDATED | 5.4 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| MCP-TPA-DESC-INJECT | 8.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| MCP-TPA-UNICODE-SMUGGLE | 8.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| MCP-TOOL-CMD-INJECT | 9.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| MCP-RES-SSRF | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| MCP-TRANSPORT-LEGACY-SSE | 5.4 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| MCP-META-HONEYPOT | 0.0 | (none — informational) |
| MCP-CVE-VERSION-MATCH | (from cves.yaml) | (omit; varies per CVE) |

- [ ] **Step 4: Update existing per-check tests**

In each `tests/unit/test_check_*.py`, replace assertions like `f.check == "AUTH-001"` with:

```python
    assert f.check == "MCP-AUTH-UNAUTH-LIST"
    assert "AUTH-001" in f.aliases
```

For `tests/integration/test_lab_full_scan.py`, update the `expected` set:

```python
    expected = {
        "MCP-AUTH-UNAUTH-LIST", "MCP-AUTH-AUDIENCE-MISBOUND", "MCP-AUTH-ORIGIN-MISVALIDATED",
        "MCP-TPA-DESC-INJECT", "MCP-TPA-UNICODE-SMUGGLE", "MCP-TOOL-CMD-INJECT",
        "MCP-RES-SSRF", "MCP-TRANSPORT-LEGACY-SSE", "MCP-META-HONEYPOT", "MCP-CVE-VERSION-MATCH",
    }
```

- [ ] **Step 5: Re-run; expect PASS**

```bash
pytest tests/unit -q && MCPMAP_LAB=on pytest tests/integration -v
```

- [ ] **Step 6: Commit**

```bash
git add src/mcpmap/audit/checks/ tests/unit/ tests/integration/
git commit -m "refactor(checks): migrate all 10 checks to canonical MCP-* IDs with CVSS vectors

Each check now uses the canonical_id from check_ids registry, declares
its legacy alias on Finding.aliases for back-compat, sets a confidence
score, attaches a CWE, ships a CVSS 3.1 vector string, and drops the
inline remediation string (renderer pulls from data/remediations.yaml)."
```

---

## Task 5: Wire `--rate` into actual rate-limiting

**Files:**
- Modify: `src/mcpmap/audit/runner.py`
- Modify: `src/mcpmap/pipeline.py`
- Create: `tests/unit/test_rate_limit.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_rate_limit.py`:

```python
import asyncio
import time
import pytest
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.runner import run_checks


class _Slow(BaseCheck):
    id = "TEST"
    intrusive = False
    async def run(self, server):
        await asyncio.sleep(0.05)
        return Finding(check=self.id, severity=Severity.LOW, title="t")


@pytest.mark.asyncio
async def test_rate_limit_caps_concurrency():
    s = Server(url="http://x/mcp")
    checks = [_Slow() for _ in range(10)]
    start = time.perf_counter()
    await run_checks(s, checks, passive=False, rate_rps=2)
    elapsed = time.perf_counter() - start
    # 10 checks at 2/s with 50ms each → must take >= ~5s, well above the 0.5s an unthrottled run takes
    assert elapsed >= 4.0, f"expected throttling, took {elapsed:.2f}s"
```

- [ ] **Step 2: Run; expect FAIL**

```bash
pytest tests/unit/test_rate_limit.py -v
```

- [ ] **Step 3: Add rate-limit to runner**

Modify `src/mcpmap/audit/runner.py`:

```python
from __future__ import annotations
import asyncio
from mcpmap.models import Server, Finding
from mcpmap.audit.base import BaseCheck


async def _throttled(coro_factory, sem: asyncio.Semaphore, min_interval: float, last_ts: list[float]):
    async with sem:
        wait = max(0.0, last_ts[0] + min_interval - asyncio.get_event_loop().time())
        if wait:
            await asyncio.sleep(wait)
        last_ts[0] = asyncio.get_event_loop().time()
        return await coro_factory()


async def run_checks(
    server: Server,
    checks: list[BaseCheck],
    passive: bool = False,
    rate_rps: int | None = None,
) -> list[Finding]:
    enabled = [c for c in checks if not (passive and c.intrusive)]
    if not rate_rps or rate_rps <= 0:
        results = await asyncio.gather(*(c.run(server) for c in enabled), return_exceptions=True)
    else:
        sem = asyncio.Semaphore(1)
        min_interval = 1.0 / rate_rps
        last_ts = [0.0]
        results = await asyncio.gather(
            *(_throttled(lambda c=c: c.run(server), sem, min_interval, last_ts) for c in enabled),
            return_exceptions=True,
        )
    return [f for f in results if isinstance(f, Finding)]
```

Modify `src/mcpmap/pipeline.py:120`:

```python
        findings[srv.url] = await run_checks(srv, all_checks(), passive=passive, rate_rps=rate)
```

- [ ] **Step 4: Re-run; expect PASS**

```bash
pytest tests/unit/test_rate_limit.py -v && pytest tests/unit -q
```

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/audit/runner.py src/mcpmap/pipeline.py tests/unit/test_rate_limit.py
git commit -m "feat(runner): enforce --rate as per-check throttling

--rate was accepted but never read. Now run_checks accepts rate_rps and
serializes check execution at the requested rate. Default behaviour
(rate_rps=None) is unchanged: full parallel via asyncio.gather."
```

---

## Task 6: Correlate findings — collapse downstream noise into a root finding

**Files:**
- Create: `src/mcpmap/audit/correlate.py`
- Modify: `src/mcpmap/audit/runner.py` (call rollup before return)
- Create: `tests/unit/test_correlate.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_correlate.py`:

```python
from mcpmap.models import Finding, Severity
from mcpmap.audit.correlate import rollup


def _f(check, sev=Severity.HIGH):
    return Finding(check=check, severity=sev, title=check)


def test_rollup_links_audience_and_origin_to_unauth_when_unauth_present():
    fs = [
        _f("MCP-AUTH-UNAUTH-LIST"),
        _f("MCP-AUTH-AUDIENCE-MISBOUND"),
        _f("MCP-AUTH-ORIGIN-MISVALIDATED"),
        _f("MCP-TOOL-CMD-INJECT"),
    ]
    out = rollup(fs)
    by_id = {f.check: f for f in out}
    assert by_id["MCP-AUTH-AUDIENCE-MISBOUND"].related_to == "MCP-AUTH-UNAUTH-LIST"
    assert by_id["MCP-AUTH-ORIGIN-MISVALIDATED"].related_to == "MCP-AUTH-UNAUTH-LIST"
    assert by_id["MCP-AUTH-UNAUTH-LIST"].related_to is None
    assert by_id["MCP-TOOL-CMD-INJECT"].related_to is None  # unrelated → standalone


def test_rollup_no_op_when_no_root():
    fs = [_f("MCP-AUTH-AUDIENCE-MISBOUND"), _f("MCP-TOOL-CMD-INJECT")]
    out = rollup(fs)
    assert all(f.related_to is None for f in out)
```

- [ ] **Step 2: Run; expect FAIL**

- [ ] **Step 3: Implement correlator**

Create `src/mcpmap/audit/correlate.py`:

```python
from __future__ import annotations
from mcpmap.models import Finding


# Each entry: child_check_id -> root_check_id. If both present in a single server's
# findings, the child is annotated with related_to=root.
_ROLLUP_RULES: dict[str, str] = {
    "MCP-AUTH-AUDIENCE-MISBOUND":  "MCP-AUTH-UNAUTH-LIST",
    "MCP-AUTH-ORIGIN-MISVALIDATED": "MCP-AUTH-UNAUTH-LIST",
}


def rollup(findings: list[Finding]) -> list[Finding]:
    present = {f.check for f in findings}
    out: list[Finding] = []
    for f in findings:
        root = _ROLLUP_RULES.get(f.check)
        if root and root in present:
            out.append(f.model_copy(update={"related_to": root}))
        else:
            out.append(f)
    return out
```

In `src/mcpmap/audit/runner.py`, call it before return:

```python
    from mcpmap.audit.correlate import rollup
    findings = [f for f in results if isinstance(f, Finding)]
    return rollup(findings)
```

- [ ] **Step 4: Re-run; expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/audit/correlate.py src/mcpmap/audit/runner.py tests/unit/test_correlate.py
git commit -m "feat(audit): correlate AUTH-* findings into root + confirmations

When a server fires AUTH-UNAUTH-LIST, the AUDIENCE-MISBOUND and
ORIGIN-MISVALIDATED findings on the same server are now linked via
Finding.related_to so the report can render them as confirmations
under the root rather than three separate criticals."
```

---

## Task 7: Render remediations + correlation in report outputs

**Files:**
- Modify: `src/mcpmap/report/markdown_out.py`
- Modify: `src/mcpmap/report/html_out.py`
- Modify: `src/mcpmap/report/templates/scan_template.html` (add remediation block + related_to indent)
- Modify: `src/mcpmap/report/poc_out.py`
- Modify: `tests/unit/test_report_json_md.py`, `test_report_html.py`, `test_poc_out.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/unit/test_report_json_md.py`:

```python
def test_markdown_renders_remediation_from_yaml():
    sr = ScanResult(scan_id="x", servers=[Server(url="http://x/mcp")],
                    findings={"http://x/mcp": [Finding(check="MCP-AUTH-UNAUTH-LIST", severity=Severity.HIGH, title="t")]})
    md = to_markdown(sr)
    assert "OAuth 2.1" in md  # comes from remediations.yaml
    assert "AUTH-001" in md   # legacy alias shown


def test_markdown_indents_correlated_findings():
    sr = ScanResult(scan_id="x", servers=[Server(url="http://x/mcp")], findings={"http://x/mcp": [
        Finding(check="MCP-AUTH-UNAUTH-LIST", severity=Severity.HIGH, title="root"),
        Finding(check="MCP-AUTH-AUDIENCE-MISBOUND", severity=Severity.HIGH, title="child", related_to="MCP-AUTH-UNAUTH-LIST"),
    ]})
    md = to_markdown(sr)
    assert "↳" in md or "  -" in md   # some visible indent for the child
```

- [ ] **Step 2: Run; expect FAIL**

- [ ] **Step 3: Implement in markdown_out.py**

Pattern:

```python
from mcpmap.audit.remediations import lookup as lookup_remediation
from mcpmap.audit.check_ids import canonical_to_legacy


def _render_finding(f: Finding) -> str:
    legacy = canonical_to_legacy(f.check)
    legacy_str = f" (legacy: {', '.join(legacy)})" if legacy else ""
    indent = "  " if f.related_to else ""
    rem = lookup_remediation(f.check)
    rem_block = f"\n{indent}  Remediation: {rem.summary.strip()}\n{indent}  References:\n" + \
                "\n".join(f"{indent}    - {ref}" for ref in rem.references) if rem else ""
    return f"{indent}- **{f.check}**{legacy_str} — {f.title} [{f.severity.value}, conf={f.confidence.value}]{rem_block}"
```

(Adapt the existing render function. Read current `markdown_out.py` and substitute. Apply the same pattern to `html_out.py` and the HTML template.)

- [ ] **Step 4: Update tests; re-run; expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/report/ tests/unit/test_report_json_md.py tests/unit/test_report_html.py tests/unit/test_poc_out.py
git commit -m "feat(report): render YAML remediations and correlation indent

Reports now pull remediation copy + references from data/remediations.yaml
at render time. Findings with related_to are indented under their parent.
Legacy IDs are shown in parens for back-compat with existing dashboards."
```

---

## Task 8: Promote `_enrich_target` to public API

**Files:**
- Modify: `src/mcpmap/pipeline.py` (rename `_enrich_target` → `enrich_target`; keep underscore as deprecated alias)
- Modify: `src/mcpmap/cli.py` (update import)

- [ ] **Step 1: Edit + test**

```python
# pipeline.py
async def enrich_target(t: Target) -> Server | None:
    ...  # body unchanged

_enrich_target = enrich_target  # back-compat
```

```python
# cli.py
from mcpmap.pipeline import run_scan, enrich_target, all_checks
```

- [ ] **Step 2: Run all tests**

```bash
pytest tests/unit -q && MCPMAP_LAB=on pytest tests/integration -v
```

- [ ] **Step 3: Commit**

```bash
git add src/mcpmap/pipeline.py src/mcpmap/cli.py
git commit -m "refactor(pipeline): promote _enrich_target to public API"
```

---

## Final verification

- [ ] **Step 1: End-to-end**

```bash
mcpmap scan 127.0.0.1 --out /tmp/scan.json --rate 5
mcpmap report /tmp/scan.json --format html --out /tmp/scan.html
mcpmap poc /tmp/scan.json --check MCP-TOOL-CMD-INJECT --out /tmp/poc.md
cat /tmp/poc.md   # must contain CWE-78, CVSS:3.1/, references[]
```

- [ ] **Step 2: Schema bump**

In `models.py`, change `schema_version: str = "1.0"` → `"1.1"` to signal the wire-format addition (new fields + optional rename).

- [ ] **Step 3: Final commit**

```bash
git add src/mcpmap/models.py
git commit -m "chore(models): bump schema_version to 1.1 (canonical IDs + Evidence + correlations)"
```

---

## Self-review pass

**Spec coverage:**
- Typed Evidence ✓ (Task 1)
- Confidence field ✓ (Task 1)
- CVSS vector strings ✓ (Tasks 1 + 4)
- CWE mapping ✓ (Tasks 1, 2, 4)
- Finding correlation/dedup ✓ (Task 6)
- Externalized remediations ✓ (Task 3)
- Renamed check IDs with deprecation aliases ✓ (Tasks 2, 4)
- `--rate` enforced ✓ (Task 5)
- `_enrich_target` promotion ✓ (Task 8)

**Placeholder scan:** Task 7's "Adapt the existing render function" is the closest thing to a placeholder — the engineer must read the current `markdown_out.py` to know which function to modify. Acceptable: that file is small and the substitution is mechanical. If executing via subagent, the subagent should `Read` the file before edit.

**Type consistency:** `canonical_id` field name consistent across `check_ids.py`, tests, and registry usage. `related_to` consistent across `models.py`, `correlate.py`, report modules. `rate_rps` consistent across `runner.py`, `pipeline.py`, `cli.py`. `aliases` (plural) is the field name on `Finding`; `legacy_aliases` (also plural) is the field on `CheckRec` — different names by design (one is "what other names this finding has been called", the other is "the registry's tuple of legacy IDs that map here"). ✓

**Out of scope (deliberately):** New checks for tool shadowing, token passthrough, markdown-image exfil, elicitation abuse — Plan 3.
