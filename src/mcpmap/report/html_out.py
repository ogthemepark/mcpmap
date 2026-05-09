from __future__ import annotations
import json
from pathlib import Path
from mcpmap.models import ScanResult, Severity

_TPL = Path(__file__).resolve().parent / "templates" / "scan_template.html"
_D3 = Path(__file__).resolve().parent / "templates" / "d3.min.js"


def to_html(result: ScanResult) -> str:
    tpl = _TPL.read_text(encoding="utf-8")
    d3 = _D3.read_text(encoding="utf-8")
    counts = {s.value: 0 for s in Severity}
    for fs in result.findings.values():
        for f in fs:
            counts[f.severity.value] += 1
    summary = f"servers: {len(result.servers)} | critical: {counts['critical']} | high: {counts['high']} | medium: {counts['medium']}"
    data = json.dumps(result.model_dump(mode='json'))
    return (tpl
            .replace("{{SCAN_ID}}", result.scan_id)
            .replace("{{SUMMARY}}", summary)
            .replace("{{D3_INLINE}}", d3)
            .replace("{{DATA_JSON}}", data))
