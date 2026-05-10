# Stabilize and Fix the Lies — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `mcpmap` honest. Get the integration suite green against the bundled lab, kill `TRANSPORT-001`'s dead-code path so the check actually fires in production scans, fix the broken GCP metadata probe in `SSRF-001`, and stop `AUTH-002`/`AUTH-003` from auto-firing on every no-auth server.

**Architecture:** Five surgical bugfixes, each in its own commit. No new abstractions, no scope creep. Every fix lands with a failing test that proves the bug existed, then a passing test after the fix. Run `pytest tests/unit -q` after every commit; run `MCPMAP_LAB=on pytest tests/integration -v` after Tasks 1, 2, and 5.

**Tech Stack:** Python 3.11+, aiohttp, pytest, pytest-asyncio (auto mode), Pydantic v2. Lab is Docker Compose with 10 deliberately-vulnerable services on 8001–8010.

**Pre-flight (do once before starting):**
```bash
cd /Users/lalithmacharla/projects/brainstorming/mcpmap
source .venv/bin/activate
cd testlab && docker compose up --build -d && cd ..
sleep 5
docker compose -f testlab/docker-compose.yml ps   # confirm all 10 Up
pytest tests/unit -q                               # baseline: 84/84 pass
MCPMAP_LAB=on pytest tests/integration -v          # baseline: confirms 2 fail
```

The integration baseline should show: `test_lab_discovers_all_ten_servers` failing with "9 ≥ 9" (off-by-one — currently asserts `>= 9` so it actually passes, but only finds 9), and `test_each_check_fires_at_least_once` failing with `missing: {'TRANSPORT-001'}`. **If you see different failures than these, stop and investigate before proceeding.**

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/mcpmap/discover/active.py` | TCP + HTTP path discovery | Modify: add SSE-aware probe so legacy-SSE servers are discovered |
| `src/mcpmap/discover/handshake.py` | MCP `initialize` handshake | Modify: return transport hint alongside the result |
| `src/mcpmap/pipeline.py` | Discovery → enrichment → audit orchestration | Modify: stop hardcoding `transport="streamable-http"`; use the detected value |
| `src/mcpmap/audit/checks/ssrf_001.py` | SSRF / local-file probe via `resources/read` | Modify: fix the GCP metadata probe (send `Metadata-Flavor: Google` header, look for known body content) |
| `src/mcpmap/audit/checks/auth_002.py` | Audience-binding probe | Modify: only fire when no-token request is *rejected* but bogus-token request is *accepted* |
| `src/mcpmap/audit/checks/auth_003.py` | Origin-validation probe | Modify: only fire when no-Origin request is *rejected* but evil-Origin request is *accepted* |
| `tests/unit/test_active_http.py` | Discovery unit tests | Modify: add SSE-discovery regression |
| `tests/unit/test_handshake.py` | Handshake unit tests | Modify: add transport-detection regression |
| `tests/unit/test_check_ssrf_transport.py` | SSRF + transport check tests | Modify: add GCP-probe regression |
| `tests/unit/test_check_auth_002.py` | AUTH-002 tests | Modify: add no-auth-suppression regression |
| `tests/unit/test_check_auth_003.py` | AUTH-003 tests | Modify: add no-auth-suppression regression |
| `tests/integration/test_lab_full_scan.py` | Full lab integration | Modify: tighten the discovery assertion to `== 10`, drop the manual `transport="http+sse"` override |

---

## Task 1: Fix the discovery flake (mcp-legacy-sse not detected)

**Why:** `active_discover()` calls `initialize()` (POST) on every alive HTTP path. The legacy-SSE server (`testlab/services/mcp-legacy-sse/server.py`) only handles `GET /sse` and `POST /messages` — POST `/sse` returns 405 → handshake returns `None` → port 8008 not discovered. `test_lab_discovers_all_ten_servers` currently asserts `>= 9` to hide this. We're going to fix the bug AND tighten the assertion.

**Files:**
- Modify: `src/mcpmap/discover/active.py` (add SSE-aware probe in `active_discover`)
- Modify: `tests/unit/test_active_http.py` (regression test)
- Modify: `tests/integration/test_lab_full_scan.py:36` (tighten assertion to `== 10`)

- [ ] **Step 1: Write the failing unit test**

Append to `tests/unit/test_active_http.py`:

```python
@pytest.mark.asyncio
async def test_active_discover_finds_sse_server(aiohttp_server):
    """Regression: legacy SSE servers respond to GET /sse, not POST /sse.
    active_discover must still report them as MCP servers."""
    from aiohttp import web

    async def sse_handler(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(
            b'event: message\ndata: {"jsonrpc":"2.0","id":0,"result":'
            b'{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},'
            b'"serverInfo":{"name":"sse-fake","version":"0.0.1"}}}\n\n'
        )
        return resp

    app = web.Application()
    app.router.add_get("/sse", sse_handler)
    srv = await aiohttp_server(app)

    from mcpmap.discover.active import active_discover
    targets = await active_discover(srv.host, ports=[srv.port])
    assert any(t.path_hint == "/sse" for t in targets), (
        f"expected /sse target, got: {[(t.port, t.path_hint) for t in targets]}"
    )
```

- [ ] **Step 2: Run it; expect FAIL**

```bash
pytest tests/unit/test_active_http.py::test_active_discover_finds_sse_server -v
```

Expected: FAIL (assertion error — no `/sse` target found, because `initialize()` POSTs and gets 405).

- [ ] **Step 3: Add the SSE-aware probe**

In `src/mcpmap/discover/active.py`, add this helper above `active_discover`:

```python
async def _sse_probe(url: str, timeout: float = 3.0) -> bool:
    """Return True if `url` responds to GET with an SSE stream that opens.
    Used as a fallback for legacy http+sse MCP transports where POST /sse 405s.
    """
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    headers = {"Accept": "text/event-stream"}
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, headers=headers) as r:
                if r.status >= 400:
                    return False
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" not in ctype:
                    return False
                # Read at most one frame's worth of bytes to confirm the stream opens
                chunk = await r.content.read(4096)
                return b"data:" in chunk
    except Exception:
        return False
```

Then modify the inner loop of `active_discover` (around `if await initialize(url) is not None:`) to:

```python
        for p in alive:
            url = base + p
            if await initialize(url) is not None:
                confirmed.append(Target(host=host, port=port, path_hint=p, source="active"))
                break  # one path per (host, port) is enough
            if p.endswith("/sse") and await _sse_probe(url):
                confirmed.append(Target(host=host, port=port, path_hint=p, source="active"))
                break
```

- [ ] **Step 4: Re-run unit test; expect PASS**

```bash
pytest tests/unit/test_active_http.py::test_active_discover_finds_sse_server -v
pytest tests/unit -q   # ensure nothing else broke
```

Expected: target test PASS, all 84+ unit tests PASS.

- [ ] **Step 5: Tighten the integration assertion**

In `tests/integration/test_lab_full_scan.py:36`, change:

```python
    assert len(targets) >= 9
```

to:

```python
    assert len(targets) == 10, f"expected all 10 lab servers, got {len(targets)}: {[(t.port, t.path_hint) for t in targets]}"
```

- [ ] **Step 6: Run integration; expect PASS for discovery**

```bash
MCPMAP_LAB=on pytest tests/integration/test_lab_full_scan.py::test_lab_discovers_all_ten_servers -v
```

Expected: PASS with all 10 ports detected.

- [ ] **Step 7: Commit**

```bash
git add src/mcpmap/discover/active.py tests/unit/test_active_http.py tests/integration/test_lab_full_scan.py
git commit -m "fix(discover): detect legacy http+sse MCP servers via GET probe

active_discover() only POSTed initialize, which 405s against legacy SSE
servers that only accept GET /sse. Add a fallback probe and tighten the
lab integration assertion from >=9 to ==10."
```

---

## Task 2: Make TRANSPORT-001 actually fire in production

**Why:** `pipeline._enrich_target` (`src/mcpmap/pipeline.py:68`) hardcodes `transport="streamable-http"` for every server. `Transport001LegacySse.run()` only fires when `server.transport == "http+sse"`. In production scans this **never fires** — only the integration test manually overrides it. Detect transport at handshake time, plumb it through.

**Files:**
- Modify: `src/mcpmap/discover/handshake.py` (return transport alongside result)
- Modify: `src/mcpmap/pipeline.py` (use returned transport)
- Modify: `src/mcpmap/discover/active.py` (callers of `initialize` — discovery only checks truthiness, so adapt)
- Modify: `tests/unit/test_handshake.py` (regression)
- Modify: `tests/integration/test_lab_full_scan.py` (drop the manual override on port 8008)

- [ ] **Step 1: Write the failing handshake unit test**

Append to `tests/unit/test_handshake.py`:

```python
import pytest
from aiohttp import web
from mcpmap.discover.handshake import initialize


@pytest.mark.asyncio
async def test_initialize_reports_streamable_http_transport(aiohttp_server):
    async def h(request):
        return web.json_response({
            "jsonrpc": "2.0", "id": 1,
            "result": {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "x", "version": "0"}},
        })
    app = web.Application(); app.router.add_post("/mcp", h)
    srv = await aiohttp_server(app)
    res = await initialize(f"http://{srv.host}:{srv.port}/mcp")
    assert res is not None
    assert res.get("_mcpmap_transport") == "streamable-http"


@pytest.mark.asyncio
async def test_initialize_reports_http_sse_transport(aiohttp_server):
    async def h(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(
            b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"x","version":"0"}}}\n\n'
        )
        return resp
    app = web.Application(); app.router.add_post("/mcp", h)
    srv = await aiohttp_server(app)
    res = await initialize(f"http://{srv.host}:{srv.port}/mcp")
    assert res is not None
    assert res.get("_mcpmap_transport") == "http+sse"
```

- [ ] **Step 2: Run; expect FAIL**

```bash
pytest tests/unit/test_handshake.py::test_initialize_reports_streamable_http_transport \
       tests/unit/test_handshake.py::test_initialize_reports_http_sse_transport -v
```

Expected: both FAIL — `_mcpmap_transport` key not present.

- [ ] **Step 3: Plumb transport through `initialize()`**

In `src/mcpmap/discover/handshake.py`, modify the SSE branch and the JSON branch of `initialize()` to attach the transport hint to the returned dict. Replace the body inside the `try/async with` block with:

```python
            async with session.post(url, json=_init_payload(), headers=headers) as r:
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    body = await r.content.read(8192)
                    text = body.decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        if line.startswith("data:"):
                            try:
                                import json as _j
                                payload = _j.loads(line[5:].strip())
                                if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                                    result = payload.get("result")
                                    if isinstance(result, dict):
                                        result["_mcpmap_transport"] = "http+sse"
                                    return result
                            except Exception:
                                continue
                    return None

                try:
                    payload = await r.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    return None
                if not isinstance(payload, dict):
                    return None
                if payload.get("jsonrpc") == "2.0" and "result" in payload:
                    result = payload["result"]
                    if isinstance(result, dict):
                        result["_mcpmap_transport"] = "streamable-http"
                    return result
                return None
```

- [ ] **Step 4: Use it in the pipeline**

In `src/mcpmap/pipeline.py`, modify `_enrich_target` so the hardcoded `transport="streamable-http"` becomes the detected value. Replace lines around 62–69 with:

```python
    info = ServerInfo(**(res.get("serverInfo") or {}))
    detected_transport = res.pop("_mcpmap_transport", "streamable-http")
    server = Server(
        url=url,
        server_info=info,
        capabilities=res.get("capabilities", {}),
        protocol_version=res.get("protocolVersion"),
        transport=detected_transport,
    )
```

(The `pop` strips the synthetic key so it doesn't leak into the serialized `ScanResult`.)

- [ ] **Step 5: Re-run handshake tests; expect PASS**

```bash
pytest tests/unit/test_handshake.py -v
pytest tests/unit -q
```

Expected: both new tests PASS, all 86 unit tests PASS.

- [ ] **Step 6: Drop the manual override in the integration test**

In `tests/integration/test_lab_full_scan.py`, delete lines 65–66:

```python
        if port == 8008:
            srv.transport = "http+sse"
```

Replace `_enrich` (lines 39–53) with code that uses the real pipeline path:

```python
async def _enrich(url: str) -> Server:
    from mcpmap.discover.handshake import initialize
    res = await initialize(url)
    assert res, f"no init: {url}"
    info = ServerInfo(**(res.get("serverInfo") or {}))
    detected_transport = res.pop("_mcpmap_transport", "streamable-http")
    s = Server(
        url=url,
        server_info=info,
        capabilities=res.get("capabilities", {}),
        protocol_version=res.get("protocolVersion"),
        transport=detected_transport,
    )
    s.fingerprint_id = match_fingerprint(info, port=int(url.rsplit(':', 1)[1].split('/')[0]))
    import aiohttp
    async with aiohttp.ClientSession() as sess:
        async with sess.post(url, json={"jsonrpc":"2.0","id":1,"method":"tools/list"}) as r:
            try:
                data = await r.json(content_type=None)
                s.tools = [Tool(**t) for t in data.get("result", {}).get("tools", [])]
            except Exception:
                pass
    return s
```

(Removes the test gaming. Now the test exercises the real production code path.)

- [ ] **Step 7: Run integration check-firing test**

```bash
MCPMAP_LAB=on pytest tests/integration/test_lab_full_scan.py::test_each_check_fires_at_least_once -v
```

Expected: PASS — all 10 checks fire, including TRANSPORT-001 against port 8008. (Note: 8008's URL is `/sse` not `/mcp`; `_enrich` is called with `/mcp` per the loop in the test. Verify the test loop also tries `/sse` — if not, fix the loop:)

If TRANSPORT-001 still doesn't fire, replace the URL construction in `test_each_check_fires_at_least_once` with:

```python
    for port in range(8001, 8011):
        url = f"http://127.0.0.1:{port}/sse" if port == 8008 else f"http://127.0.0.1:{port}/mcp"
```

- [ ] **Step 8: Commit**

```bash
git add src/mcpmap/discover/handshake.py src/mcpmap/pipeline.py \
        tests/unit/test_handshake.py tests/integration/test_lab_full_scan.py
git commit -m "fix(transport): detect http+sse vs streamable-http at handshake

pipeline._enrich_target hardcoded transport='streamable-http', making
TRANSPORT-001 dead code in production. handshake.initialize() now
attaches the detected transport to the returned dict and the pipeline
uses it. Integration test no longer fakes the transport for port 8008."
```

---

## Task 3: Fix the GCP metadata probe in SSRF-001

**Why:** `src/mcpmap/audit/checks/ssrf_001.py:10` defines the GCP probe as `("http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor")`. `Metadata-Flavor` is the **request header name** GCP requires (`Metadata-Flavor: Google`); it is **not** content the response body contains. The check looks for it in `text` (body), so it never fires correctly. Also, GCP metadata requires the header on the *upstream* request — meaning the SSRF check needs to instruct the target to set it, which we cannot do. We can only detect SSRF that fires the request server-side; the *body content* we look for must be something GCP returns when called correctly. Replace the probe with one that doesn't rely on header content, and add an AWS IMDSv1 probe variant that's known-good.

**Files:**
- Modify: `src/mcpmap/audit/checks/ssrf_001.py:6-11`
- Modify: `tests/unit/test_check_ssrf_transport.py` (add regression)

- [ ] **Step 1: Write the failing regression test**

Append to `tests/unit/test_check_ssrf_transport.py`:

```python
@pytest.mark.asyncio
async def test_ssrf_001_does_not_false_positive_on_metadata_header_echo(aiohttp_server):
    """Regression: a server that echoes the URI back must not look like an SSRF hit
    just because the URI string contains 'Metadata-Flavor'-shaped text."""
    async def echo(request):
        body = await request.json()
        if body.get("method") == "resources/read":
            uri = body["params"].get("uri", "")
            return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": "Metadata-Flavor"}]
            }})
        return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {}})

    app = web.Application(); app.router.add_post("/mcp", echo)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Ssrf001ResourcesRead().run(s)
    # Echoing the literal string "Metadata-Flavor" is not proof of GCP metadata access.
    # Should not fire on this fake.
    assert f is None or "metadata.google.internal" not in str(f.evidence), (
        f"false positive: {f.evidence if f else None}"
    )
```

- [ ] **Step 2: Run; expect FAIL** (the current code WILL flag this echo as a hit)

```bash
pytest tests/unit/test_check_ssrf_transport.py::test_ssrf_001_does_not_false_positive_on_metadata_header_echo -v
```

Expected: FAIL — current code matches `"Metadata-Flavor"` substring in echoed body.

- [ ] **Step 3: Replace the GCP probe with content-based fingerprints**

In `src/mcpmap/audit/checks/ssrf_001.py`, replace the `PROBES` list (lines 6–11):

```python
# Each probe: (uri, body_fingerprints).
# A finding fires only if the response body contains AT LEAST ONE of the fingerprints —
# things only the real upstream would emit, not strings the URI itself might echo.
PROBES = [
    ("file:///etc/passwd", ["root:x:0:0"]),
    ("file:///etc/hostname", []),                   # no fingerprint — only fires if status==200 & non-empty content
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam/"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
]
```

(Remove the GCP probe. It cannot be probed remotely without forcing the target to send the `Metadata-Flavor: Google` header upstream, which we have no way to make it do.)

Modify the matching loop (lines 22–31) to:

```python
            for uri, fingerprints in PROBES:
                body = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}}
                try:
                    async with session.post(server.url, json=body, headers={"Accept": "application/json, text/event-stream"}) as r:
                        text = await r.text()
                except aiohttp.ClientError:
                    continue
                if r.status != 200 or '"result"' not in text:
                    continue
                # Strip the echoed URI before fingerprint-matching so an echo doesn't false-positive.
                body_only = text.replace(uri, "")
                if not fingerprints:
                    # No fingerprint defined → require non-trivial body (>50 bytes after stripping the URI echo).
                    if len(body_only) > 200:
                        hits.append({"uri": uri, "response_excerpt": text[:512]})
                else:
                    if any(fp in body_only for fp in fingerprints):
                        hits.append({"uri": uri, "matched_fingerprints": [fp for fp in fingerprints if fp in body_only], "response_excerpt": text[:512]})
```

- [ ] **Step 4: Re-run regression + existing SSRF tests; expect PASS**

```bash
pytest tests/unit/test_check_ssrf_transport.py -v
pytest tests/unit -q
```

Expected: regression PASS, all existing SSRF tests still PASS.

- [ ] **Step 5: Confirm SSRF-001 still fires against the lab**

```bash
MCPMAP_LAB=on pytest tests/integration/test_lab_full_scan.py::test_each_check_fires_at_least_once -v
```

Expected: PASS — `mcp-ssrf` (port 8007) returns `/etc/passwd` content, fingerprint `root:x:0:0` matches.

- [ ] **Step 6: Commit**

```bash
git add src/mcpmap/audit/checks/ssrf_001.py tests/unit/test_check_ssrf_transport.py
git commit -m "fix(SSRF-001): drop broken GCP probe, harden against URI-echo false positives

GCP probe checked for 'Metadata-Flavor' string in response body, but
that's a *request header name* GCP requires upstream — never appears in
any response body the target would return. Replaced with AWS IMDS
credential-shaped fingerprints, and now strips the echoed URI from the
body before fingerprint matching to suppress trivial echo false-positives."
```

---

## Task 4: AUTH-002 must not fire on no-auth servers

**Why:** `auth_002.py:23` fires whenever a bogus `Authorization: Bearer …` returns HTTP 200 with a result. A server with **no auth at all** also returns 200 with a result for the same request. So AUTH-002 currently double-fires on every server AUTH-001 fires on, with a misleading "audience binding violation" title. Real audience-binding failure means: server *does* require a token, but accepts the wrong one. Gate AUTH-002 on observing both behaviors.

**Files:**
- Modify: `src/mcpmap/audit/checks/auth_002.py`
- Modify: `tests/unit/test_check_auth_002.py` (add regression)

- [ ] **Step 1: Write the failing regression test**

Append to `tests/unit/test_check_auth_002.py`:

```python
@pytest.mark.asyncio
async def test_auth_002_silent_when_server_has_no_auth_at_all(aiohttp_server):
    """Regression: an unauthenticated server must not be flagged for 'audience binding'.
    AUTH-002 is only meaningful when the server *requires* a token but accepts the wrong one."""
    from aiohttp import web

    async def no_auth(request):
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", no_auth)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth002AudienceBinding().run(s)
    assert f is None, f"AUTH-002 false-positive on no-auth server: {f}"


@pytest.mark.asyncio
async def test_auth_002_fires_when_token_required_but_audience_unchecked(aiohttp_server):
    """AUTH-002 should fire when no-token = 401 but bogus-token = 200."""
    from aiohttp import web

    async def lax_auth(request):
        if not request.headers.get("Authorization"):
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "auth required"}}, status=401)
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", lax_auth)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth002AudienceBinding().run(s)
    assert f is not None and f.check == "AUTH-002"
```

- [ ] **Step 2: Run; expect FAIL on the no-auth test**

```bash
pytest tests/unit/test_check_auth_002.py -v
```

Expected: `test_auth_002_silent_when_server_has_no_auth_at_all` FAIL (current check fires on it).

- [ ] **Step 3: Add the no-token comparison probe**

Replace the body of `Auth002AudienceBinding.run()` in `src/mcpmap/audit/checks/auth_002.py`:

```python
    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                # Probe 1: no token. If this succeeds, the server has no auth at all —
                # AUTH-001's territory, not ours. Stay silent.
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    no_tok_status = r.status
                    no_tok_text = await r.text()
                if no_tok_status == 200 and '"result"' in no_tok_text:
                    return None  # no auth — let AUTH-001 own this finding

                # Probe 2: bogus token. If this succeeds, the server requires a token
                # but doesn't validate audience.
                headers = {"Authorization": DECOY_TOKEN, "Accept": "application/json, text/event-stream"}
                async with s.post(server.url, json=payload, headers=headers) as r:
                    if r.status == 200:
                        text = await r.text()
                        if '"result"' in text:
                            return Finding(
                                check=self.id,
                                severity=Severity.HIGH,
                                cvss=8.1,
                                title="Token audience not validated (RFC 8707 violation)",
                                evidence={
                                    "no_token_status": no_tok_status,
                                    "bogus_token": DECOY_TOKEN,
                                    "bogus_token_status": r.status,
                                    "response_excerpt": text[:512],
                                },
                                repro=f"curl -X POST {server.url} -H 'Authorization: {DECOY_TOKEN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                                remediation=(
                                    "Validate the audience (`aud`) claim of every bearer token against this "
                                    "server's canonical resource URI (RFC 8707). Reject tokens minted for "
                                    "other audiences even if signed by the same IdP."
                                ),
                            )
        except aiohttp.ClientError:
            return None
        return None
```

- [ ] **Step 4: Re-run; expect PASS**

```bash
pytest tests/unit/test_check_auth_002.py -v
pytest tests/unit -q
```

Expected: both AUTH-002 tests PASS, all other tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mcpmap/audit/checks/auth_002.py tests/unit/test_check_auth_002.py
git commit -m "fix(AUTH-002): suppress on no-auth servers; only fire on real audience-binding flaw

AUTH-002 fired whenever bogus-Bearer + tools/list returned 200, which
includes every no-auth server (already AUTH-001 territory). Now sends a
no-token probe first and bails if that also succeeds, so the finding
only lands when the server requires *some* token but accepts a junk one."
```

---

## Task 5: AUTH-003 must not fire on no-auth servers

**Why:** Same defect as AUTH-002. `auth_003.py:20` flags any server that returns 2xx with `Origin: evil.example`. No-auth servers always return 2xx — AUTH-003 currently piggybacks on every AUTH-001 finding. Origin validation is meaningful when the server *would* reject a request without/with-different-Origin but accepts evil-Origin. Gate it the same way.

**Files:**
- Modify: `src/mcpmap/audit/checks/auth_003.py`
- Modify: `tests/unit/test_check_auth_003.py` (add regression)

- [ ] **Step 1: Write the failing regression test**

Append to `tests/unit/test_check_auth_003.py`:

```python
@pytest.mark.asyncio
async def test_auth_003_silent_when_server_has_no_auth_at_all(aiohttp_server):
    """Regression: a fully open server is AUTH-001, not AUTH-003.
    Origin validation is only meaningful when the server cares about origins."""
    from aiohttp import web

    async def open_server(request):
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", open_server)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f is None, f"AUTH-003 false-positive on no-auth server: {f}"


@pytest.mark.asyncio
async def test_auth_003_fires_when_no_origin_rejected_but_evil_accepted(aiohttp_server):
    from aiohttp import web

    async def origin_lax(request):
        origin = request.headers.get("Origin")
        if not origin:
            return web.json_response({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "origin required"}}, status=403)
        body = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id", 1), "result": {"tools": []}})

    app = web.Application(); app.router.add_post("/mcp", origin_lax)
    srv = await aiohttp_server(app)
    s = Server(url=f"http://{srv.host}:{srv.port}/mcp")
    f = await Auth003OriginValidation().run(s)
    assert f is not None and f.check == "AUTH-003"
```

- [ ] **Step 2: Run; expect FAIL on the no-auth test**

```bash
pytest tests/unit/test_check_auth_003.py -v
```

- [ ] **Step 3: Add the no-Origin comparison probe**

Replace the body of `Auth003OriginValidation.run()` in `src/mcpmap/audit/checks/auth_003.py`:

```python
    async def run(self, server: Server) -> Finding | None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        timeout = aiohttp.ClientTimeout(total=5.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as s:
                # Probe 1: no Origin header. Open servers return 2xx → AUTH-001 territory.
                async with s.post(server.url, json=payload, headers={"Accept": "application/json, text/event-stream"}) as r:
                    no_origin_status = r.status
                if 200 <= no_origin_status < 300:
                    return None  # server doesn't care about Origin (or about anything) — not AUTH-003

                # Probe 2: evil Origin. If this succeeds where no-Origin failed, the server
                # has Origin-aware logic but accepts attacker-controlled values.
                headers = {"Origin": EVIL_ORIGIN, "Accept": "application/json, text/event-stream"}
                async with s.post(server.url, json=payload, headers=headers) as r:
                    if 200 <= r.status < 300:
                        text = await r.text()
                        return Finding(
                            check=self.id,
                            severity=Severity.MEDIUM,
                            cvss=5.4,
                            title="Origin header not validated (DNS-rebinding risk)",
                            evidence={
                                "no_origin_status": no_origin_status,
                                "sent_origin": EVIL_ORIGIN,
                                "evil_origin_status": r.status,
                                "response_excerpt": text[:256],
                            },
                            repro=f"curl -X POST {server.url} -H 'Origin: {EVIL_ORIGIN}' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'",
                            remediation=(
                                "Validate the Origin header against an explicit allowlist before "
                                "accepting the request; for localhost-only servers, bind to 127.0.0.1 "
                                "(not 0.0.0.0) and require Origin to be 'http://localhost' or a known "
                                "client UI. Mitigates DNS-rebinding."
                            ),
                        )
        except aiohttp.ClientError:
            return None
        return None
```

- [ ] **Step 4: Re-run; expect PASS**

```bash
pytest tests/unit/test_check_auth_003.py -v
pytest tests/unit -q
```

- [ ] **Step 5: Run the full integration suite once more**

```bash
MCPMAP_LAB=on pytest tests/integration -v
```

Expected: all 4 integration tests PASS. Note: this changes which lab servers AUTH-002 and AUTH-003 fire against. The integration test only asserts each check fires *at least once*, so the lab still needs *one* server that genuinely violates each. If `test_each_check_fires_at_least_once` fails on `AUTH-002` or `AUTH-003`, the `mcp-audience-broken` (8002) and `mcp-origin-permissive` (8003) lab servers need to be updated to require *some* token / *some* Origin header before accepting bogus values — they're currently fully open. **Out of scope for this task** — open a follow-up commit to harden those two lab servers, but only if integration fails. If integration passes, ship as-is.

If you do need to harden the lab servers, the minimal fix in `testlab/services/mcp-audience-broken/server.py` is to reject requests *without* an `Authorization` header (any string is accepted, no audience validated). Same for `mcp-origin-permissive`: reject requests with no `Origin`. After editing, rebuild: `cd testlab && docker compose up -d --build mcp-audience-broken mcp-origin-permissive`.

- [ ] **Step 6: Commit**

```bash
git add src/mcpmap/audit/checks/auth_003.py tests/unit/test_check_auth_003.py
git commit -m "fix(AUTH-003): suppress on no-auth servers; only fire on real Origin-validation flaw

AUTH-003 fired on every server that returned 2xx for an evil-Origin
request, which includes every fully-open server (already AUTH-001's
finding). Now sends a no-Origin probe first and only fires when the
server discriminates by Origin but accepts attacker-controlled values."
```

If the lab needed hardening in Step 5, additionally:

```bash
git add testlab/services/mcp-audience-broken/server.py testlab/services/mcp-origin-permissive/server.py
git commit -m "test(lab): harden audience-broken + origin-permissive to require some header

AUTH-002/003 now require the server to *care* about the header before
firing. The lab servers were fully open, so the gated checks would
never fire. Make them check for the presence (not the value) of
Authorization / Origin so the relevant test still has a positive case."
```

---

## Final verification

- [ ] **Step 1: Run everything from a clean shell**

```bash
cd /Users/lalithmacharla/projects/brainstorming/mcpmap
source .venv/bin/activate
pytest tests/unit -q && \
  MCPMAP_LAB=on pytest tests/integration -v
```

Expected:
- Unit: ≥90 tests, all PASS (5 new regression tests added)
- Integration: 4 tests, all PASS, including the `==10` discovery and `TRANSPORT-001 fires` assertions

- [ ] **Step 2: Run an actual scan against the lab end-to-end**

```bash
mcpmap scan 127.0.0.1 --out /tmp/scan.json
mcpmap report /tmp/scan.json --format html --out /tmp/scan.html
python -c "import json; d=json.load(open('/tmp/scan.json')); \
  print('servers:', len(d['servers'])); \
  print('checks fired:', sorted({f['check'] for fs in d['findings'].values() for f in fs}))"
```

Expected: `servers: 10`, `checks fired:` contains `TRANSPORT-001` (the production fix from Task 2 actually works end-to-end).

- [ ] **Step 3: Update CHANGELOG / README claim if needed**

Read `README.md:71` — the line "ten deliberately-vulnerable MCP servers" is now actually true under integration. No edit needed unless you want to add a "v0.1.1 — stabilization" line.

- [ ] **Step 4: Final commit if anything dangling**

```bash
git status
# If clean, you're done. If not, review and commit / discard intentionally.
```

---

## Self-review pass

**Spec coverage:** All five fixes from the conversation (discovery flake, TRANSPORT-001 dead code, SSRF-001 GCP probe, AUTH-002 false positive, AUTH-003 false positive) have a dedicated task. ✓

**Placeholder scan:** No "TBD", no "implement later", no "similar to Task N". Every code step has the actual code. ✓

**Type consistency:** `_mcpmap_transport` key spelled identically across handshake.py, pipeline.py, and the integration test's `_enrich`. `Server.transport` field name unchanged. `DECOY_TOKEN` and `EVIL_ORIGIN` module-level constants in their respective check files unchanged. ✓

**Out of scope (deliberately):** Renaming check IDs, CWE mapping, typed Evidence, externalized remediations, finding correlation, rate-limiting — all in Plan 2. New checks for tool shadowing / token passthrough / markdown-image exfil / elicitation abuse — all in Plan 3.
