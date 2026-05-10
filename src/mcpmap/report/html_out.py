from __future__ import annotations
import json
from pathlib import Path
from mcpmap.models import ScanResult, Severity

_TPL = Path(__file__).resolve().parent / "templates" / "scan_template.html"


def to_html(result: ScanResult) -> str:
    tpl = _TPL.read_text(encoding="utf-8")
    counts = {s.value: 0 for s in Severity}
    for fs in result.findings.values():
        for f in fs:
            counts[f.severity.value] += 1
    data = json.dumps(result.model_dump(mode='json')).replace("</", r"<\/")
    return (tpl
            .replace("{{SCAN_ID}}", result.scan_id)
            .replace("{{DATA_JSON}}", data))
