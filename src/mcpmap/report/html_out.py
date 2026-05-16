from __future__ import annotations
import html as _html
import json
from pathlib import Path
from mcpmap.models import ScanResult

_TPL = Path(__file__).resolve().parent / "templates" / "scan_template.html"


def _enrich_findings(result: ScanResult) -> ScanResult:
    """Pre-populate f.remediation from YAML for findings where it is None."""
    from mcpmap.audit.remediations import lookup as lookup_remediation
    new_findings = {}
    for url, fs in result.findings.items():
        new_fs = []
        for f in fs:
            if f.remediation is None:
                rem = lookup_remediation(f.check)
                if rem:
                    f = f.model_copy(update={"remediation": rem.summary})
            new_fs.append(f)
        new_findings[url] = new_fs
    return result.model_copy(update={"findings": new_findings})


def to_html(result: ScanResult) -> str:
    result = _enrich_findings(result)
    tpl = _TPL.read_text(encoding="utf-8")
    data = json.dumps(result.model_dump(mode='json')).replace("</", r"<\/")
    # Replace DATA_JSON first so a malicious scan_id containing "{{DATA_JSON}}"
    # cannot cause a nested substitution.
    return (tpl
            .replace("{{DATA_JSON}}", data)
            .replace("{{SCAN_ID}}", _html.escape(result.scan_id)))
