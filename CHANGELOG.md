# Changelog

All notable changes to **mcpmap** are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-05-16

Initial public release. mcpmap is the "nmap for MCP servers": discover,
fingerprint, and audit [Model Context Protocol](https://modelcontextprotocol.io/)
servers across a network, with paste-ready disclosure writeups.

### Added

- **Three-stage async pipeline** — `discover → fingerprint → audit → report`,
  composed in `src/mcpmap/pipeline.py`.
- **Discovery sources**
  - Active scan: TCP sweep over prioritized ports → HTTP path probe →
    MCP `initialize` handshake (`discover/active.py`). Supports streamable-HTTP
    and legacy `http+sse` transports.
  - Shodan: 26-query categorized sweep (`discover/shodan_source.py`,
    `data/shodan_filters.json` forked from
    [Knostic's MCP-Scanner](https://github.com/knostic/MCP-Scanner)).
  - Local stdio configs: Claude Desktop, Cursor, Continue, etc.
    (`discover/configs.py`).
- **Fingerprinting** — matches `serverInfo` against `data/fingerprints.yaml`
  and cross-references known CVEs from `data/cves.yaml`
  (CVE-2025-49596, CVE-2025-6514, CVE-2025-54136, CVE-2025-53967, …).
- **Audit check matrix** — 10 checks covering:
  - Auth: `MCP-AUTH-UNAUTH-LIST`, `MCP-AUTH-AUDIENCE-MISBOUND`,
    `MCP-AUTH-ORIGIN-MISVALIDATED`
  - Tool integrity: `MCP-TOOL-POISON-DESC`, `MCP-TOOL-CMD-INJECT`
  - Network: `MCP-RES-SSRF`, `MCP-TRANSPORT-WEAK`
  - Operational: `MCP-HONEYPOT-DETECT`, `MCP-CVE-MATCH`
  - All check IDs registered in `audit/check_ids.py` with CWE,
    default severity, and legacy aliases for back-compat.
- **Concurrent, rate-limited check runner** (`audit/runner.py`) using
  `asyncio.gather` + optional token-bucket throttling via `--rate`.
- **Finding correlator** (`audit/correlate.py`) — collapses dependent
  findings under a root via `related_to`, so reports don't duplicate noise.
- **Typed finding model** (`models.py`) — `Evidence`, `Confidence`, CWE,
  CVSS vector. Serialized `ScanResult` is `schema_version: "1.1"` and is
  the stable contract between scanning and reporting.
- **Reporters** — JSON (canonical), Markdown, and offline-first
  self-contained HTML (no CDN/font fetches at runtime). Per-finding
  coordinated-disclosure markdown writeup via `mcpmap poc`.
- **CLI** (`mcpmap`) — `discover`, `fingerprint`, `audit`, `scan`,
  `configs`, `report`, `poc`. Global flags: `--passive`, `--rate`,
  `--verbose`.
- **Test lab** (`testlab/`) — 10 deliberately-vulnerable MCP servers on
  ports 8001–8010, orchestrated via docker-compose. One service per
  vulnerability for clean repro.
- **Test suite** — 119 unit tests + integration suite gated by
  `MCPMAP_LAB=on` that asserts every check fires against the lab at
  least once.
- **Packaging** — `pyproject.toml` (hatchling), Python ≥3.11.
  Installable via `uv sync`, `pip install -e .`, or the bundled
  `Dockerfile` (~208 MB image, non-root user, includes the Shodan extra).
- **Docs** — `README.md` (pipeline walkthrough, lab evidence, install
  matrix, Shodan how-to), `CLAUDE.md` (architecture + contributor guide),
  `docs/ETHICS.md` (authorized-testing policy), `docs/ATTRIBUTIONS.md`,
  `docs/DEMO.md`, `testlab/README.md`.

### Security

- All scanning is gated by an "authorized testing only" notice at CLI
  start. Intrusive checks (`MCP-TOOL-CMD-INJECT`, `MCP-RES-SSRF`) are
  skipped under `--passive` for production triage.

[Unreleased]: https://github.com/ogthemepark/mcpmap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ogthemepark/mcpmap/releases/tag/v0.1.0
