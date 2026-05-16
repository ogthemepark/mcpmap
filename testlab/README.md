# mcpmap test lab

Ten deliberately-vulnerable MCP servers, one per check. **Never expose these outside Docker.**

## Boot

```bash
docker compose up --build -d
```

Each service binds to 127.0.0.1:8001..8010. Smoke-test:

```bash
curl -s -X POST http://127.0.0.1:8001/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

## Mapping (check → port)

| Port | Service | Demonstrates |
|---|---|---|
| 8001 | mcp-noauth | `MCP-AUTH-UNAUTH-LIST` — no auth on `tools/list` |
| 8002 | mcp-audience-broken | `MCP-AUTH-AUDIENCE-MISBOUND` — accepts any bearer (RFC 8707) |
| 8003 | mcp-origin-permissive | `MCP-AUTH-ORIGIN-MISVALIDATED` — permissive `Origin` |
| 8004 | mcp-poisoned | `MCP-TPA-DESC-INJECT` — prompt-injection markers in description |
| 8005 | mcp-unicode | `MCP-TPA-UNICODE-SMUGGLE` — zero-width / unicode-tag chars |
| 8006 | mcp-cmdinject | `MCP-TOOL-CMD-INJECT` — shell injection via tool argument |
| 8007 | mcp-ssrf | `MCP-RES-SSRF` — `resources/read` SSRF |
| 8008 | mcp-legacy-sse | `MCP-TRANSPORT-LEGACY-SSE` — deprecated `http+sse` |
| 8009 | mcp-honeypot | `MCP-META-HONEYPOT` — stable session id, empty tools |
| 8010 | mcp-cve-figma | `MCP-CVE-VERSION-MATCH` — vulnerable version banner |
