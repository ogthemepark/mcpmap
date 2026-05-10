from __future__ import annotations
from dataclasses import dataclass
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
