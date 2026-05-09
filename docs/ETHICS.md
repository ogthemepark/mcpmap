# Ethics & responsible use

`mcpmap` is an offensive security tool. Active scanning of systems you do not own or have explicit written permission to test is illegal in most jurisdictions (CFAA in the US, the Computer Misuse Act in the UK, equivalent laws elsewhere).

## Before you scan

- [ ] You own the target, **or**
- [ ] You have written authorization (engagement letter, scope document, bug-bounty program rules) covering the exact targets and types of probes you will run.

## Use the lab

The bundled `testlab/` runs ten deliberately-vulnerable MCP servers locally in Docker. Use it for development, demos, and learning.

## Responsible disclosure

If you find a vulnerable MCP server in the wild during authorized testing:

1. **Do not exploit** beyond what's needed to confirm the bug class.
2. **Report privately** to the operator. Templates below.
3. **Coordinate disclosure** — give the operator a reasonable window (industry standard: 90 days) before publishing.
4. **CERT-class escalation** for unresponsive vendors:
   - US: CERT/CC <https://www.kb.cert.org/vuls/report/>
   - EU: ENISA / national CSIRT
   - Or vendor-specific PSIRT contact (Anthropic, Cloudflare, etc.)

## Disclosure email template

```
Subject: Security finding in <product / endpoint> — coordinated disclosure

Hi <team>,

I'm a security researcher and I identified a vulnerability in <product / endpoint>:

- Class: <e.g., command injection in MCP tool argument>
- Affected: <URL / version>
- Evidence: <attached reproduction>
- Risk: <CVSS / impact>

I'm following responsible-disclosure practice: 90 days before any public mention.
Please confirm receipt and a remediation timeline.

Tools used: mcpmap (https://github.com/<you>/mcpmap)
```

## What `mcpmap` will not do

- Scan without your explicit target argument.
- Bypass authentication beyond confirming an audience-binding flaw.
- Persist tool calls or escalate beyond the configured intrusive probes.

You are the operator. Use it well.
