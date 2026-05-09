# Attributions

`mcpmap` builds on substantial public work. Specific debts:

## Code

- **Shodan filter list** (`data/shodan_filters.json`) is forked from [Knostic Inc.'s MCP-Scanner](https://github.com/knostic/MCP-Scanner) (MIT-licensed). Their public-internet MCP recon work made this category visible.

## Methodology

- [Bitsight — Exposed MCP servers](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities) — discovery methodology, honeypot patterns, fingerprint heuristics
- [Knostic — Find MCP server with Shodan](https://www.knostic.ai/blog/find-mcp-server-shodan) — Shodan dorks and handshake-based identification
- [Anthropic MCP specification](https://modelcontextprotocol.io/specification/) — protocol semantics
- [Authzed — Timeline of MCP breaches](https://authzed.com/blog/timeline-mcp-breaches) — CVE corpus

## Vulnerability research

- [Invariant Labs — Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Invariant Labs — GitHub MCP Data Heist](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [Embrace the Red — MCP unicode-tag exploit chain](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/)
- [JFrog — CVE-2025-6514 mcp-remote RCE](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [Oligo — CVE-2025-49596 MCP Inspector RCE](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
- [Check Point — Cursor MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/)
- [Endor Labs — Framelink Figma command injection](https://www.endorlabs.com/learn/cve-2025-53967-remote-code-execution-in-framelink-figma-mcp-server)
- [Simon Willison — Lethal Trifecta framing](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [HiddenLayer — Lethal Trifecta defense](https://www.hiddenlayer.com/research/the-lethal-trifecta-and-how-to-defend-against-it)
- [Elastic Security Labs — MCP attack/defense](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
