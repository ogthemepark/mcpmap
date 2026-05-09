from __future__ import annotations
import json
import os
from pathlib import Path
from mcpmap.models import Target

try:
    import shodan  # type: ignore
except ImportError:
    shodan = None  # graceful: tool runs without the optional extra


_FILTERS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "shodan_filters.json"


def load_filters() -> dict[str, list[str]]:
    """Read the categorized Shodan filter list."""
    raw = json.loads(_FILTERS_PATH.read_text(encoding="utf-8"))
    return raw.get("filters", {})


def shodan_targets(
    api_key: str | None = None,
    queries: list[str] | None = None,
    max_per_query: int = 50,
) -> list[Target]:
    """Query Shodan and return deduplicated Targets.

    `api_key` may be the literal key, an env var name, or None (uses SHODAN_API_KEY).
    Returns [] if no key, no library, or any API failure.
    """
    if shodan is None:
        return []
    key = api_key or os.environ.get("SHODAN_API_KEY")
    if not key:
        return []

    if queries is None:
        cats = load_filters()
        # Use only the most signal-rich categories for the default sweep:
        queries = []
        for k in ("core_mcp", "transport_layer", "endpoints", "frameworks"):
            queries.extend(cats.get(k, []))

    api = shodan.Shodan(key)
    seen: set[tuple[str, int]] = set()
    out: list[Target] = []
    for q in queries:
        try:
            res = api.search(q, limit=max_per_query)
        except Exception:
            continue  # quota/rate-limit/syntax — skip this filter
        for m in res.get("matches", []):
            ip = m.get("ip_str")
            port = m.get("port")
            if not (ip and port):
                continue
            key_ip = (ip, int(port))
            if key_ip in seen:
                continue
            seen.add(key_ip)
            out.append(Target(host=ip, port=int(port), source="shodan"))
    return out
