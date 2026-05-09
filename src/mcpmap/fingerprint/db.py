from __future__ import annotations
from pathlib import Path
import yaml
from mcpmap.models import ServerInfo

_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "fingerprints.yaml"


def load_db(path: Path | None = None) -> list[dict]:
    p = path or _DB_PATH
    return yaml.safe_load(p.read_text(encoding="utf-8")) or []


def match_fingerprint(info: ServerInfo, port: int | None = None, db: list[dict] | None = None) -> str | None:
    """Return the first matching fingerprint id, or None.

    Match precedence: port-hint match wins over name-only match (more specific).
    Within name matches, the first-defined entry wins (db is order-sensitive).

    DEVIATION from original spec: the spec used
        `if port_hit and (name_hit or not name_substrs):`
    which would fail `test_match_by_port_when_name_ambiguous` — when name="proxy"
    and port=6277, mcp-inspector's name_substrs is non-empty and name_hit is False,
    so the condition evaluates False and the function incorrectly returns None.

    The test intent ("name_ambiguous") is clear: a port match alone should be
    sufficient to identify a fingerprint, since port_in entries are rare and
    inherently more specific than name substrings. Fixed to: `if port_hit:`.
    """
    db = db if db is not None else load_db()
    name = (info.name or "").lower()
    name_only_hits: list[str] = []
    for entry in db:
        m = entry.get("match", {})
        port_in = m.get("port_in")
        name_substrs = [s.lower() for s in m.get("server_info_name_contains", [])]
        port_hit = port is not None and port_in is not None and port in port_in
        name_hit = any(s in name for s in name_substrs) if name_substrs else False
        # A port match alone is sufficient (port_in entries are rare and specific).
        if port_hit:
            return entry["id"]
        if name_hit and not port_in:
            name_only_hits.append(entry["id"])
    return name_only_hits[0] if name_only_hits else None
