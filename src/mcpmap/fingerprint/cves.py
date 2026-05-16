from __future__ import annotations
from pathlib import Path
import yaml
from packaging.version import Version, InvalidVersion
from pydantic import BaseModel

_CVES_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cves.yaml"


class CveEntry(BaseModel):
    fingerprint_id: str
    cve: str
    title: str
    severity: str
    cvss: float
    affected: str
    verified: bool = False
    source: str = ""


def _load() -> list[CveEntry]:
    raw = yaml.safe_load(_CVES_PATH.read_text(encoding="utf-8")) or []
    return [CveEntry(**e) for e in raw]


def _safe_version(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def in_range(version: str, spec: str) -> bool:
    """Tiny range-spec evaluator: supports `*`, `>=X`, `>X`, `<=X`, `<X`, comma-joined ANDs."""
    if spec.strip() == "*":
        return True
    v = _safe_version(version)
    if v is None:
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        op = ""
        for candidate in (">=", "<=", ">", "<", "=="):
            if clause.startswith(candidate):
                op = candidate
                rest = clause[len(candidate):].strip()
                break
        else:
            return False
        target = _safe_version(rest)
        if target is None:
            return False
        cmp = {
            ">=": v >= target,
            ">":  v > target,
            "<=": v <= target,
            "<":  v < target,
            "==": v == target,
        }
        if not cmp[op]:
            return False
    return True


def cves_for(fingerprint_id: str, version: str) -> list[CveEntry]:
    return [e for e in _load() if e.fingerprint_id == fingerprint_id and in_range(version, e.affected)]
