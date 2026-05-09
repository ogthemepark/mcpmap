from __future__ import annotations
from mcpmap.models import ScanResult, Severity

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"# mcpmap scan report — {result.scan_id}")
    lines.append("")
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for fs in result.findings.values():
        for f in fs:
            counts[f.severity.value] += 1
    lines.append("## Summary")
    lines.append(f"- Servers: {len(result.servers)}")
    lines.append(f"- Findings: {sum(counts.values())} (critical: {counts['critical']}, high: {counts['high']}, medium: {counts['medium']}, low: {counts['low']}, info: {counts['info']})")
    lines.append("")

    for srv in result.servers:
        lines.append(f"## {srv.url}")
        lines.append(f"- Fingerprint: `{srv.fingerprint_id or 'unknown'}`")
        lines.append(f"- Server: `{srv.server_info.name} {srv.server_info.version}`")
        lines.append(f"- Transport: `{srv.transport}`")
        lines.append(f"- Tools: {len(srv.tools)}")
        fs = result.findings.get(srv.url, [])
        if not fs:
            lines.append("- _No findings._")
            lines.append("")
            continue
        fs_sorted = sorted(fs, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        lines.append("")
        lines.append("| Check | Severity | CVSS | Title |")
        lines.append("|---|---|---|---|")
        for f in fs_sorted:
            cvss = f"{f.cvss}" if f.cvss is not None else "-"
            lines.append(f"| `{f.check}` | **{f.severity.value}** | {cvss} | {f.title} |")
        lines.append("")
    return "\n".join(lines)
