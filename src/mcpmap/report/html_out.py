from __future__ import annotations
import html as _html
import json
from pathlib import Path
from mcpmap.models import ScanResult

_TPL = Path(__file__).resolve().parent / "templates" / "scan_template.html"


def to_html(result: ScanResult) -> str:
    tpl = _TPL.read_text(encoding="utf-8")
    data = json.dumps(result.model_dump(mode='json')).replace("</", r"<\/")
    # Replace DATA_JSON first so a malicious scan_id containing "{{DATA_JSON}}"
    # cannot cause a nested substitution.
    return (tpl
            .replace("{{DATA_JSON}}", data)
            .replace("{{SCAN_ID}}", _html.escape(result.scan_id)))
