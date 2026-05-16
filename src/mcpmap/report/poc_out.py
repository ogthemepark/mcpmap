"""Per-finding proof-of-concept markdown writeup, suitable for paste into a
HackerOne / Jira / coordinated-disclosure report."""
from __future__ import annotations
import json
from mcpmap.models import ScanResult, Finding, Server
from mcpmap.audit.check_ids import legacy_to_canonical
from mcpmap.audit.remediations import lookup as lookup_remediation


def _norm_check(check: str) -> str:
    """Normalize legacy IDs to canonical so branch ladders only need canonical IDs."""
    canon = legacy_to_canonical(check)
    return canon or check


_HEADER = """# Security Finding: {check} — {title}

**Target:** {url}
**Server:** `{server_name} {server_version}`
**Fingerprint:** `{fingerprint}`
**Severity:** {severity_upper} (CVSS {cvss})
**Discovered:** {scan_id} via mcpmap
"""


def _curl_for(check: str, url: str, finding: Finding) -> str:
    """Reconstruct a runnable curl from finding evidence."""
    c = _norm_check(check)
    raw_ev = finding.evidence
    ev = raw_ev.model_dump(exclude_none=True) if hasattr(raw_ev, "model_dump") else (raw_ev or {})
    # Flatten artifacts into the top-level dict so legacy key lookups (e.g. "hits") still work.
    artifacts = ev.pop("artifacts", {}) or {}
    ev = {**artifacts, **ev}
    if c == "MCP-TOOL-CMD-INJECT":
        hits = ev.get("hits") or []
        if not hits:
            return ""
        h = hits[0]
        tool_name = h.get("tool", "unknown_tool")
        arg_name = h.get("arg", "arg")
        payload = h.get("payload", "")
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool_name, "arguments": {arg_name: payload}},
        }
        return _curl(url, body)
    if c == "MCP-RES-SSRF":
        hits = ev.get("hits") or []
        if not hits:
            return ""
        uri = hits[0].get("uri", "")
        if not uri:
            return ""
        body = {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": {"uri": uri}}
        return _curl(url, body)
    if c in ("MCP-AUTH-UNAUTH-LIST", "MCP-AUTH-AUDIENCE-MISBOUND", "MCP-AUTH-ORIGIN-MISVALIDATED"):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        return _curl(url, body, extra_headers=_extra_for(c))
    if c == "MCP-META-HONEYPOT":
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        return _curl(url, body) + "\n# Repeat 3 times; observe identical Mcp-Session-Id."
    if c in ("MCP-TPA-DESC-INJECT", "MCP-TPA-UNICODE-SMUGGLE", "MCP-CVE-VERSION-MATCH"):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        return _curl(url, body) + "\n# Inspect the returned tool descriptions / serverInfo.version."
    if c == "MCP-TRANSPORT-LEGACY-SSE":
        return f"curl -s -H 'Accept: text/event-stream' {url}\n# Server speaks deprecated http+sse."
    return _curl(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def _extra_for(check: str) -> list[str]:
    c = _norm_check(check)
    if c == "MCP-AUTH-AUDIENCE-MISBOUND":
        return ["-H 'Authorization: Bearer mcpmap.decoy.unrelated-audience.AAAAAAAA'"]
    if c == "MCP-AUTH-ORIGIN-MISVALIDATED":
        return ["-H 'Origin: https://evil.example'"]
    return []


def _curl(url: str, body: dict, extra_headers: list[str] | None = None) -> str:
    headers = ["-H 'Content-Type: application/json'",
               "-H 'Accept: application/json, text/event-stream'"]
    if extra_headers:
        headers.extend(extra_headers)
    payload = json.dumps(body, indent=2, ensure_ascii=True).replace("'", r"\u0027")
    return (f"curl -s -X POST {url} \\\n  "
            + " \\\n  ".join(headers) + " \\\n  "
            + f"-d '{payload}'")


def _server_for(scan: ScanResult, url: str) -> Server | None:
    for s in scan.servers:
        if s.url == url:
            return s
    return None


def render_poc(scan: ScanResult, check_id: str) -> str:
    """Render a markdown PoC for the first matching finding of `check_id`."""
    for url, findings in scan.findings.items():
        for f in findings:
            if f.check != check_id:
                continue
            srv = _server_for(scan, url)
            sname = srv.server_info.name if srv and srv.server_info else "unknown"
            sver = srv.server_info.version if srv and srv.server_info else "?"
            sfp = (srv.fingerprint_id if srv else None) or "unknown"
            parts: list[str] = []
            parts.append(_HEADER.format(
                check=f.check, title=f.title, url=url,
                server_name=sname, server_version=sver, fingerprint=sfp,
                severity_upper=f.severity.value.upper(), cvss=f.cvss,
                scan_id=scan.scan_id,
            ))
            parts.append("## Summary\n")
            parts.append(f.title + "\n")
            parts.append("## Evidence\n")
            ev = f.evidence.model_dump(exclude_none=True) if hasattr(f.evidence, "model_dump") else (f.evidence or {})
            if ev:
                parts.append("```json\n" + json.dumps(ev, indent=2) + "\n```\n")
            else:
                parts.append("(no structured evidence)\n")
            parts.append("## Reproduction\n")
            curl = _curl_for(f.check, url, f)
            if curl:
                parts.append("```bash\n" + curl + "\n```\n")
            if f.repro:
                parts.append(f"**Notes:** {f.repro}\n")
            parts.append("## Remediation\n")
            remediation_text = f.remediation
            rem = lookup_remediation(f.check)
            if not remediation_text and rem:
                remediation_text = rem.summary
            parts.append((remediation_text or "_(none provided)_") + "\n")
            # References: YAML references + CVE if any
            ref_lines: list[str] = []
            if rem and rem.references:
                ref_lines.extend(f"- {r}" for r in rem.references)
            if f.cve:
                ref_lines.append(f"- {f.cve}")
            if ref_lines:
                parts.append("## References\n")
                parts.append("\n".join(ref_lines) + "\n")
            parts.append("\n---\nGenerated by mcpmap.\n")
            return "\n".join(parts)
    return f"# No findings matched check {check_id}\n"
