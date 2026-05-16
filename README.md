# mcpmap

> **Nmap for MCP servers.** Discover, fingerprint, and audit Model Context Protocol servers across networks — and produce paste-ready disclosure writeups for what you find.

⚠️ **Authorized testing only.** You are responsible for ensuring permission to scan any target. See [`docs/ETHICS.md`](docs/ETHICS.md). A safe, isolated `testlab/` is bundled for development.

---

## What this is

`mcpmap` is a small, focused offensive-security tool for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem. One command takes you from "what IP range should I look at?" to a self-contained HTML report and a markdown PoC ready to send.

It does three things end-to-end:

1. **Discover** MCP servers across hosts/CIDRs (active scan), in Shodan, or in local configs (Claude Desktop, Cursor, etc.).
2. **Fingerprint** them — framework, version, capabilities, and known CVEs.
3. **Audit** each one with a matrix of 10 vulnerability checks covering auth, tool-poisoning, command injection, SSRF, transport, and honeypot detection.

The output is a deterministic JSON document (`schema_version: "1.1"`), a markdown report, a self-contained HTML dashboard, or a per-finding disclosure PoC — all from the same scan artifact.

---

## Install

Two ways, pick whichever fits how you ship things. (Not on PyPI yet — clone or build the image.)

### Docker (recommended — works the same on every host)

```bash
docker build -t mcpmap .
docker run --rm mcpmap --help
```

The image is ~208 MB, ships with the Shodan extra installed, and runs as a non-root user. Scan a target and write the result back to your host:

```bash
docker run --rm -v "$PWD":/workspace mcpmap scan 10.0.0.0/24 --out /workspace/scan.json
```

Two networking modes for reaching targets from inside the container:

- **Reach host-published ports** (e.g. the bundled testlab on `127.0.0.1:8001–8010`):
  ```bash
  docker run --rm --add-host=host.docker.internal:host-gateway \
    -v "$PWD":/workspace mcpmap \
    scan host.docker.internal --out /workspace/scan.json
  ```
  (On Linux you can also use `--network host` and keep `127.0.0.1` as the target.)

- **Join the testlab's Docker network** and reach services by name:
  ```bash
  docker run --rm --network testlab_default \
    -v "$PWD":/workspace mcpmap \
    fingerprint http://mcp-cve-figma:8000/mcp
  ```

### From source with [uv](https://docs.astral.sh/uv/) (fastest)

```bash
git clone https://github.com/<you>/mcpmap && cd mcpmap
uv sync                              # installs everything from uv.lock
uv run mcpmap --help                 # run it
```

That's it. `uv sync` creates `.venv/` and installs the locked dependencies; `uv run` executes inside that venv without you activating it.

### From source with pip

```bash
git clone https://github.com/<you>/mcpmap && cd mcpmap
pip install -e ".[dev,shodan]"
```

Python 3.11+ required. For the lab demo you also need Docker.

---

## Quickstart (90 seconds, no real targets needed)

```bash
# 1. Spin up the safe test lab (10 deliberately-vulnerable MCP servers)
cd testlab && docker compose up -d && cd ..

# 2. Scan it
mcpmap scan 127.0.0.1 --out scan.json

# 3. Render the report
mcpmap report scan.json --format html --out scan.html
open scan.html

# 4. Generate a paste-ready disclosure PoC for one finding
mcpmap poc scan.json --check MCP-TOOL-CMD-INJECT --out inject-poc.md
```

That's the whole loop: discover → audit → report → disclose.

---

## Commands

| Command | Purpose |
|---|---|
| `mcpmap discover <target>` | Find MCP servers (active scan, Shodan, or local config files). |
| `mcpmap fingerprint <url>` | Identify framework / version / capabilities. |
| `mcpmap audit <url>` | Run the vulnerability check matrix against one server. |
| `mcpmap scan <target>` | Full pipeline: discover → fingerprint → audit. |
| `mcpmap poc <scan.json> --check <ID>` | Render a per-finding markdown PoC for coordinated disclosure. |
| `mcpmap configs` | Audit local stdio MCP configs (Claude Desktop, Cursor, etc.). |
| `mcpmap report <scan.json>` | Render JSON / Markdown / HTML from a scan artifact. |

Flags:
- `--passive` — skip intrusive checks (`MCP-TOOL-CMD-INJECT`, `MCP-RES-SSRF`); safe for production triage.
- `--rate <rps>` — cap requests-per-second per check across the whole scan (token-bucket throttling).

---

## Shodan discovery (optional)

`mcpmap` can pull candidate MCP servers from [Shodan](https://www.shodan.io/) instead of (or alongside) active scanning. This is gated behind the `shodan` extra and a Shodan API key.

**Get an API key.** Shodan's search API is **not free** — a free account only gives you browser search. You need at minimum the one-time **Membership** plan (advertised at \$49, frequently on sale to \$5; check [the pricing page](https://www.shodan.io/pricing)). `.edu` email holders can request a free upgrade.

**Configure.**

```bash
pip install -e ".[shodan]"          # or: uv sync --extra shodan
export SHODAN_API_KEY="<your-key>"
```

**Use it.**

```bash
# Discover only (one query, one credit):
mcpmap discover '"Model Context Protocol"' --shodan

# Full pipeline via Shodan (note the shodan: prefix on the target):
mcpmap scan 'shodan:"Model Context Protocol"' --out shodan-scan.json
```

**Credit burn.** `mcpmap discover --shodan` *without* a query string fires the default sweep — ~26 categorized queries from [`data/shodan_filters.json`](data/shodan_filters.json) (core MCP terms, transport markers, endpoints, frameworks). That's ~26 query credits per run. The \$5 Membership tier starts with 100. Pass an explicit query (as shown above) to burn just one.

**Authorization.** Shodan returns real internet-facing hosts. `mcpmap scan` then sends probe traffic and (unless `--passive`) intrusive payloads to those hosts. **Only scan systems you have written permission to test.** See [`docs/ETHICS.md`](docs/ETHICS.md).

---

## How it works

The whole tool is a three-stage async pipeline (`src/mcpmap/pipeline.py`):

```
┌──────────┐    ┌─────────────┐    ┌────────┐    ┌──────────┐
│ Discover │ -> │ Fingerprint │ -> │ Audit  │ -> │ Report   │
└──────────┘    └─────────────┘    └────────┘    └──────────┘
   active           serverInfo +     10 checks      JSON / MD
   Shodan           CVE match        rate-limited   HTML / PoC
   configs                           correlated
```

### 1. Discover (`src/mcpmap/discover/`)

For a target like `10.0.0.0/24` or `127.0.0.1`:

1. TCP sweep over `PRIORITY_PORTS` (MCP commonly lives on 8000–8010, 3000, 8443).
2. HTTP path probe over `MCP_PATHS` (`/mcp`, `/sse`, `/`) — alive means status `<400` or one of `{401, 403, 405}`. We *don't* loosen this to `<500`; 404s would otherwise be misreported as MCP candidates.
3. MCP `initialize` handshake — only servers that speak the protocol pass through. Both streamable-HTTP and legacy `http+sse` are detected at this step.

Alternate sources: `shodan_source.py` (queries Shodan dorks forked from Knostic) and `configs.py` (local stdio configs from Claude Desktop, Cursor, Continue, etc.).

### 2. Fingerprint (`src/mcpmap/fingerprint/`)

Matches `serverInfo.name`/`version` against `data/fingerprints.yaml`, then cross-references `data/cves.yaml`. Picks up framework identity (FastMCP, Inspector, mcp-remote, framelink-figma-mcp, …) and any known CVEs (CVE-2025-49596, CVE-2025-6514, CVE-2025-54136, CVE-2025-53967, etc.).

### 3. Audit (`src/mcpmap/audit/`)

`audit/runner.py:run_checks` fans out every `BaseCheck` subclass concurrently via `asyncio.gather`, optionally throttled by `--rate`. Each check returns a `Finding | None`. Intrusive checks (those that mutate target state) are gated by `--passive`.

The finding model (`src/mcpmap/models.py`) is the wire-format contract — typed `Evidence`, `Confidence`, CVSS vector, CWE, legacy aliases, `related_to` for correlation. Findings carry three things the renderer needs:
- `evidence` — machine-readable proof,
- `repro` — one-line reproduction guidance,
- `remediation` — operator-facing fix, pulled from `data/remediations.yaml` at render time.

A post-processing **correlator** (`audit/correlate.py`) collapses related findings. Example: if `MCP-AUTH-UNAUTH-LIST` and `MCP-AUTH-AUDIENCE-MISBOUND` both fire on the same server, the audience check is marked `related_to` the root, so the report renders it as a sub-bullet rather than duplicate noise.

### 4. Report (`src/mcpmap/report/`)

Same `ScanResult` → multiple emitters. JSON is the canonical artifact; markdown and HTML render from it; the per-finding `poc` writeup is a separate markdown emitter that reconstructs a runnable `curl` from the evidence. The HTML is **offline-first** — no CDN, no font fetches at runtime — so it's safe to open on an air-gapped triage host.

### Vulnerability check matrix

| Canonical ID | Legacy | Severity | CWE | Probe |
|---|---|---|---|---|
| `MCP-AUTH-UNAUTH-LIST` | AUTH-001 | High | CWE-306 | unauthenticated `tools/list` / `resources/list` |
| `MCP-AUTH-AUDIENCE-MISBOUND` | AUTH-002 | High | CWE-1220 | RFC 8707 audience-binding (two-probe) |
| `MCP-AUTH-ORIGIN-MISVALIDATED` | AUTH-003 | Medium | CWE-346 | Origin header not validated (DNS-rebinding) |
| `MCP-TPA-DESC-INJECT` | POISON-001 | High | CWE-77 | regex hits on tool descriptions |
| `MCP-TPA-UNICODE-SMUGGLE` | POISON-002 | High | CWE-176 | unicode-tag / zero-width characters |
| `MCP-TOOL-CMD-INJECT` | INJECT-001 | Critical | CWE-78 | canary-echo command injection |
| `MCP-RES-SSRF` | SSRF-001 | High | CWE-918 | `resources/read` with dangerous URI schemes |
| `MCP-TRANSPORT-LEGACY-SSE` | TRANSPORT-001 | Medium | CWE-1188 | legacy `http+sse` transport |
| `MCP-META-HONEYPOT` | HONEYPOT-001 | Info | — | identical session ID / empty tools |
| `MCP-CVE-VERSION-MATCH` | CVE-001 | varies | — | fingerprint → CVE match |

---

## Evidence it works

The bundled `testlab/` is the proof. Boot it and the scanner finds every server and fires every check:

```bash
$ cd testlab && docker compose up -d && cd ..
$ mcpmap scan 127.0.0.1 --out scan.json
wrote scan.json  servers=10 findings=18
```

Per-server breakdown from a fresh run (canonical IDs, `schema_version: "1.1"`):

| Lab service | Port | Findings |
|---|---|---|
| `mcp-noauth` | 8001 | `MCP-AUTH-UNAUTH-LIST` |
| `mcp-audience-broken` | 8002 | `MCP-AUTH-AUDIENCE-MISBOUND` |
| `mcp-origin-permissive` | 8003 | `MCP-AUTH-ORIGIN-MISVALIDATED` |
| `mcp-poisoned` | 8004 | `MCP-AUTH-UNAUTH-LIST`, `MCP-TPA-DESC-INJECT` |
| `mcp-unicode` | 8005 | `MCP-AUTH-UNAUTH-LIST`, `MCP-TPA-DESC-INJECT`, `MCP-TPA-UNICODE-SMUGGLE` |
| `mcp-cmdinject` | 8006 | `MCP-AUTH-UNAUTH-LIST`, `MCP-TOOL-CMD-INJECT` |
| `mcp-ssrf` | 8007 | `MCP-AUTH-UNAUTH-LIST`, `MCP-RES-SSRF`, `MCP-META-HONEYPOT` |
| `mcp-legacy-sse` | 8008 | `MCP-TRANSPORT-LEGACY-SSE` |
| `mcp-honeypot` | 8009 | `MCP-AUTH-UNAUTH-LIST`, `MCP-META-HONEYPOT` |
| `mcp-cve-figma` | 8010 | `MCP-AUTH-UNAUTH-LIST`, `MCP-CVE-VERSION-MATCH` |

**Totals:** 10/10 servers discovered, 10/10 distinct checks fire, 18 findings — 2 critical, 12 high, 2 medium, 2 info.

**Test suite:** `pytest tests/unit -q` → **119 passed**. The integration suite (`MCPMAP_LAB=on pytest tests/integration -v`) re-runs the full pipeline against the live lab and asserts every check fires at least once.

**Sample PoC output** (`mcpmap poc scan.json --check MCP-TOOL-CMD-INJECT`):

```
# Security Finding: MCP-TOOL-CMD-INJECT — Command injection via tool argument (canary echo)
**Target:** http://127.0.0.1:8006/mcp
**Server:** `mcp-cmdinject 0.0.1`
**Severity:** CRITICAL (CVSS 9.0)
...
## Evidence
{ "hits": [{ "tool": "cat_file", "arg": "path",
             "payload": "; echo MCPMAP_CANARY_2bab...",
             "response_excerpt": "...MCPMAP_CANARY_2bab..." }] }
```

The canary in the response excerpt is the proof: the tool executed the injected shell snippet.

---

## The HTML report

`mcpmap report scan.json --format html --out scan.html` produces a single, self-contained dashboard:

- **Severity strip** — five-color summary (critical / high / medium / low / info), click a segment to filter.
- **Server roster** — per-server severity breakdown, click to filter the finding list.
- **Finding list** — sorted critical-first; sigils (▣ ◆ ◈ ○ ·) double-encode severity for grayscale / colorblind viewing. Correlated findings are indented under their root with a `↳` glyph.
- **Detail pane** — evidence JSON, reconstructed `curl` PoC, and the remediation guidance from `data/remediations.yaml`. The `copy as curl` button replays the exact request that triggered the finding.
- **Keyboard:** `j` / `k` next & previous finding, `/` focuses search, `c` copies the current curl, `Esc` clears selection.

Offline-first: no CDN fetches, no fonts pulled at runtime. Open it on a triage host air-gapped from the scanned network.

---

## Background & prior art

The MCP ecosystem grew faster than its security tooling. As of mid-2026:

- **~1,000+** public MCP servers without auth ([Bitsight](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities))
- **119/119** servers in [Knostic's Shodan study](https://www.knostic.ai/blog/find-mcp-server-shodan) allowed unauth `tools/list`
- 12 months of public CVEs: [CVE-2025-49596 (Inspector RCE)](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596), [CVE-2025-6514 (mcp-remote RCE)](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/), [CVE-2025-54136 (Cursor MCPoison)](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/), [CVE-2025-53967 (Framelink Figma)](https://www.endorlabs.com/learn/cve-2025-53967-remote-code-execution-in-framelink-figma-mcp-server), and more (see [Authzed's MCP-breach timeline](https://authzed.com/blog/timeline-mcp-breaches)).

Existing tooling either scans static config files (`mcp-scan`, Snyk Agent Scan) or queries Shodan (Knostic). Nothing actively scans, fingerprints, *and* audits MCP servers across a network in one pass. `mcpmap` fills that gap.

### What this builds on

`mcpmap` stands on a stack of prior work — see [`docs/ATTRIBUTIONS.md`](docs/ATTRIBUTIONS.md) for the full list. The key sources:

**Reconnaissance methodology**
- [Bitsight — Exposed MCP servers](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities) — discovery methodology, honeypot patterns, fingerprint heuristics
- [Knostic — Find MCP server with Shodan](https://www.knostic.ai/blog/find-mcp-server-shodan) — Shodan dorks and handshake-based identification. Our `data/shodan_filters.json` is forked from [Knostic Inc.'s MCP-Scanner](https://github.com/knostic/MCP-Scanner) (MIT).

**Vulnerability research**
- [Invariant Labs — Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — basis for `MCP-TPA-DESC-INJECT`
- [Invariant Labs — GitHub MCP Data Heist](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [Embrace the Red — MCP unicode-tag exploit chain](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/) — basis for `MCP-TPA-UNICODE-SMUGGLE`
- [Simon Willison — Lethal Trifecta framing](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [HiddenLayer — Lethal Trifecta defense](https://www.hiddenlayer.com/research/the-lethal-trifecta-and-how-to-defend-against-it)
- [Elastic Security Labs — MCP attack/defense](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)

**Protocol & spec**
- [Anthropic MCP specification](https://modelcontextprotocol.io/specification/) — protocol semantics, transport flavors, capability negotiation

---

## Documentation

- [`docs/ETHICS.md`](docs/ETHICS.md) — authorization, responsible disclosure, scope discipline
- [`docs/ATTRIBUTIONS.md`](docs/ATTRIBUTIONS.md) — credit to the prior art this builds on
- [`docs/DEMO.md`](docs/DEMO.md) — reproduce the lab demo step-by-step
- [`testlab/README.md`](testlab/README.md) — what each lab service demonstrates, port by port
- [`CLAUDE.md`](CLAUDE.md) — architecture notes for contributors and AI assistants

## Contributing

The MCP threat landscape moves quickly, and `mcpmap` is most useful when its check matrix, fingerprint database, and CVE corpus track what defenders are actually seeing in the wild. Contributions that extend any of these are especially welcome:

- **A new audit check** — see `src/mcpmap/audit/base.py` for the interface and `src/mcpmap/audit/check_ids.py` for the canonical-ID registry. New checks should ship with a paired deliberately-vulnerable lab service under `testlab/services/` so the integration suite can prove the check fires.
- **Fingerprint or CVE entries** — `data/fingerprints.yaml` and `data/cves.yaml`. The bar is low: a server name, a version range, and a citation.
- **Remediation copy** — `data/remediations.yaml`. Operator-facing language that actually helps someone fix the finding is genuinely hard to write; good edits here go a long way.
- **Prior-art pointers we've missed** — a writeup of a novel attack technique, a CVE we haven't catalogued, or a fingerprint heuristic from your own recon work.

Issues and ideas count too. The project is small enough that a thoughtful bug report or a "have you considered..." often translates directly into the next release. Before opening a PR please read [`docs/ETHICS.md`](docs/ETHICS.md) and run `pytest tests/unit -q` (and the lab integration suite if your change touches scanning behavior). For security-sensitive reports about `mcpmap` itself, please use a private channel rather than a public issue.

If `mcpmap` is useful to you, the most valuable thing you can do is tell us where it fell short — silent users teach the project nothing, and the gap between "scanner that works on a lab" and "scanner that works on the messy real internet" is closed one honest report at a time.

## License

MIT — see [LICENSE](LICENSE).
