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
| 8001 | mcp-noauth | AUTH-001 (no auth on tools/list) |
| 8002 | mcp-audience-broken | AUTH-002 (accepts any bearer) |
| 8003 | mcp-origin-permissive | AUTH-003 (permissive Origin) |
| 8004 | mcp-poisoned | POISON-001 (TPA in description) |
| 8005 | mcp-unicode | POISON-002 (zero-width / tag chars) |
| 8006 | mcp-cmdinject | INJECT-001 (shell injection) |
| 8007 | mcp-ssrf | SSRF-001 (resources/read SSRF) |
| 8008 | mcp-legacy-sse | TRANSPORT-001 (deprecated http+sse) |
| 8009 | mcp-honeypot | HONEYPOT-001 (stable session id) |
| 8010 | mcp-cve-figma | CVE-001 (vulnerable version banner) |
