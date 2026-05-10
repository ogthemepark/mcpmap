# mcpmap

> **Nmap for MCP servers.** Discover, fingerprint, and audit Model Context Protocol servers across networks.

⚠️ **Authorized testing only.** You are responsible for ensuring permission to scan any target. See [`docs/ETHICS.md`](docs/ETHICS.md).

## Why

The MCP ecosystem grew fast. As of mid-2026:

- ~1000+ public MCP servers without auth (Bitsight)
- 119/119 servers in Knostic's study allowed unauth `tools/list`
- 12 months of CVEs: CVE-2025-49596 (Inspector RCE), CVE-2025-6514 (mcp-remote RCE), CVE-2025-54136 (Cursor MCPoison), CVE-2025-53967 (Framelink Figma), and more.

Existing tooling either scans config files (`mcp-scan`, Snyk Agent Scan) or queries Shodan (Knostic). Nothing actively scans, fingerprints, *and* audits MCP servers across a network. `mcpmap` is that tool.

## Install

```bash
pip install mcpmap                  # core
pip install mcpmap[shodan]          # + Shodan source
```

Or from source:
```bash
git clone https://github.com/<you>/mcpmap && cd mcpmap
pip install -e ".[dev,shodan]"
```

## Quickstart

```bash
# 1. Spin up the test lab
cd testlab && docker compose up -d && cd ..

# 2. Scan it
mcpmap scan 127.0.0.1 --out scan.json

# 3. Render the HTML map
mcpmap report scan.json --format html --out scan.html
open scan.html
```

## From scan to coordinated-disclosure report

Capture findings, then export a paste-ready writeup for one of them:

```bash
mcpmap scan 127.0.0.1 --out scan.json
mcpmap poc scan.json --check INJECT-001 --out inject-poc.md
# inject-poc.md is now ready to paste into HackerOne / Jira / email.
```

You can also browse findings with full evidence inline:

```bash
mcpmap audit http://127.0.0.1:8006/mcp --verbose
```

## The HTML report

`mcpmap report scan.json --format html --out scan.html` produces a single, self-contained dashboard:

- **Severity strip** — five-color summary (critical / high / medium / low / info), click a segment to filter.
- **Server roster** — per-server severity breakdown, click to filter the finding list.
- **Finding list** — sorted critical-first; sigils (▣ ◆ ◈ ○ ·) double-encode severity for grayscale / colorblind viewing.
- **Detail pane** — evidence JSON, reconstructed `curl` PoC, and the remediation guidance from Cycle A. The `copy as curl` button replays the exact request that triggered the finding.
- **Keyboard:** `j` / `k` next & previous finding, `/` focuses search, `c` copies the current curl, `Esc` clears selection.

The report is offline-first: no CDN fetches, no fonts pulled at runtime. Open it on a triage host air-gapped from the scanned network.

## Commands

| Command | Purpose |
|---|---|
| `mcpmap discover <target>` | Find MCP servers (active scan, Shodan, file). |
| `mcpmap fingerprint <url>` | Identify framework / version / capabilities. |
| `mcpmap audit <url>` | Run vulnerability check matrix. |
| `mcpmap scan <target>` | Pipeline: discover → fingerprint → audit. |
| `mcpmap poc <scan.json> --check <ID>` | Render a per-finding markdown PoC for coordinated disclosure. |
| `mcpmap configs` | Audit local stdio MCP configs (Claude Desktop, Cursor, etc.). |
| `mcpmap report <scan.json>` | Render JSON / Markdown / HTML. |

`--passive` opts out of intrusive checks (INJECT-001, SSRF-001).

## Vulnerability check matrix (v1)

| ID | Severity | Probe |
|---|---|---|
| AUTH-001 | High | unauth `tools/list` / `resources/list` |
| AUTH-002 | High | RFC 8707 audience-binding |
| AUTH-003 | Medium | Origin header not validated |
| POISON-001 | High | TPA regex on tool descriptions |
| POISON-002 | High | unicode-tag / zero-width detection |
| INJECT-001 | Critical | canary-echo command injection |
| SSRF-001 | High | `resources/read` schema disclosure |
| TRANSPORT-001 | Medium | legacy HTTP+SSE detected |
| HONEYPOT-001 | Info | identical session ID / empty tools |
| CVE-001 | varies | fingerprint → CVE match |

## Documentation

- [`docs/ETHICS.md`](docs/ETHICS.md) — authorization, responsible disclosure, scope discipline
- [`docs/ATTRIBUTIONS.md`](docs/ATTRIBUTIONS.md) — credit to the prior art this builds on
- [`docs/DEMO.md`](docs/DEMO.md) — reproduce the lab demo end-to-end
- `docs/superpowers/specs/` — full design spec
- `docs/superpowers/plans/` — implementation plan (this file)

## License

MIT — see [LICENSE](LICENSE).
