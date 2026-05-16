# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mcpmap` is an offensive security tool ("nmap for MCP servers") that discovers, fingerprints, and audits Model Context Protocol servers. **All scanning must be authorized** (`docs/ETHICS.md`); the bundled `testlab/` is the safe target for development.

## Commands

Install (editable, with dev + optional Shodan source):
```bash
uv sync                              # preferred — uses uv.lock
pip install -e ".[dev,shodan]"       # equivalent
```

Tests:
```bash
pytest tests/unit -v                     # fast, no docker
cd testlab && docker compose up --build -d && cd ..
MCPMAP_LAB=on pytest tests/integration -v   # requires lab running
pytest tests/unit/test_check_inject_001.py::test_name   # single test
```

The `MCPMAP_LAB=on` env var is the gate for the integration suite — without it, `tests/integration/` is skipped (see `tests/integration/test_lab_full_scan.py:20`).

Lint: `ruff check .` (config in `pyproject.toml`, line-length 100, target py311).

CLI entrypoint: `mcpmap` (declared in `pyproject.toml` → `mcpmap.cli:app`). End-to-end demo: `mcpmap scan 127.0.0.1 --out scan.json && mcpmap report scan.json --format html --out scan.html`.

## Architecture

Three-stage pipeline composed in `src/mcpmap/pipeline.py`:

1. **Discover** (`discover/`) — `active.py` does TCP sweep over `PRIORITY_PORTS` → HTTP path probe over `MCP_PATHS` → MCP `initialize` handshake. Alternate sources: `shodan_source.py`, `configs.py` (local stdio configs from Claude Desktop / Cursor / etc.).
2. **Fingerprint** (`fingerprint/`) — `db.py` matches `serverInfo` against `data/fingerprints.yaml`; `cves.py` cross-references `data/cves.yaml`.
3. **Audit** (`audit/`) — `runner.run_checks` fans out all `BaseCheck` subclasses concurrently via `asyncio.gather` (optionally throttled by `--rate`, see `_throttled`). Each check in `audit/checks/*.py` returns a `Finding` or `None`. Checks set `intrusive = True` if they mutate target state (`MCP-TOOL-CMD-INJECT`, `MCP-RES-SSRF`) — those are skipped when `--passive`. After fan-out, `audit/correlate.py:rollup` stamps `related_to` on dependent findings so reports can collapse confirmation noise under a root finding.

`models.py` is the canonical schema (Pydantic). The serialized `ScanResult` (`scan.json`, `schema_version: "1.1"`) is the contract between scanning and reporting — keep it stable. Check IDs are canonical `MCP-*` (e.g. `MCP-AUTH-UNAUTH-LIST`); legacy short IDs (`AUTH-001`, `INJECT-001`, etc.) are maintained as aliases in `src/mcpmap/audit/check_ids.py`.

**Reporting** (`report/`) emits the same `ScanResult` as JSON, Markdown, or self-contained HTML. The HTML template is `report/templates/scan_template.html`; per the README it must stay offline-first (no CDN/font fetches at runtime). `poc_out.py` renders single-finding markdown writeups for coordinated disclosure (`mcpmap poc`).

### Adding a new audit check

1. Pick a canonical ID (`MCP-<DOMAIN>-<SLUG>`) and register it in `src/mcpmap/audit/check_ids.py` with CWE + default severity/confidence. Add any legacy alias too.
2. Create `src/mcpmap/audit/checks/<slug>.py` with a class subclassing `BaseCheck`, set `id = "<canonical>"`, `intrusive` if applicable, implement `async def run(self, server: Server) -> Finding | None`.
3. Register it in `pipeline.all_checks()` *and* in the integration test's `ALL_CHECKS` list (`tests/integration/test_lab_full_scan.py`) — the integration test asserts every check fires at least once against the lab.
4. Add a remediation entry keyed by canonical ID in `data/remediations.yaml` (summary + references). The renderer (`report/*`) pulls remediation copy from there; checks themselves leave `Finding.remediation = None`.
5. Add a deliberately-vulnerable target service under `testlab/services/<name>/server.py` and wire it into `testlab/docker-compose.yml` on the next free `800X:8000` port (current range 8001–8010).
6. Add a unit test under `tests/unit/test_check_<slug>.py`.

### Async patterns

Everything network-facing is `async`. The CLI uses `asyncio.run(...)` at the boundary; `cli.audit` has a thread-trampoline (`_run`) so it can be invoked from inside an already-running event loop (e.g. pytest-asyncio). Reuse this pattern if you add commands that run inside other loops.

## Conventions worth knowing

- `pytest-asyncio` is in `auto` mode (`pyproject.toml`) — async tests don't need a decorator.
- `http_paths_alive` treats `< 400` plus `{401, 403, 405}` as "alive" (path exists). Don't loosen to `< 500` — `active.py:64` has the rationale; 404s would otherwise be reported as MCP candidates.
- Findings carry `evidence` (machine-readable), `repro` (one-line curl-equivalent), and `remediation` (operator guidance). The HTML detail pane and the `poc` writeup both depend on all three being populated — see `tests/unit/test_remediation_populated.py`.
