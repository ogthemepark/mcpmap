from __future__ import annotations
from mcpmap.models import ScanResult


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
