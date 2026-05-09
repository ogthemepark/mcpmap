from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity
from mcpmap.audit.base import BaseCheck

PROBES = [
    ("file:///etc/passwd", "root:x:0:0"),
    ("file:///etc/hostname", None),
    ("http://169.254.169.254/latest/meta-data/", "iam"),
    ("http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor"),
]


class Ssrf001ResourcesRead(BaseCheck):
    id = "SSRF-001"
    intrusive = True

    async def run(self, server: Server) -> Finding | None:
        timeout = aiohttp.ClientTimeout(total=10.0)
        hits: list[dict] = []
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
            for uri, fingerprint in PROBES:
                body = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}}
                try:
                    async with session.post(server.url, json=body, headers={"Accept": "application/json, text/event-stream"}) as r:
                        text = await r.text()
                except aiohttp.ClientError:
                    continue
                if r.status == 200 and '"result"' in text:
                    if fingerprint is None or fingerprint in text:
                        hits.append({"uri": uri, "response_excerpt": text[:512]})
        if not hits:
            return None
        return Finding(
            check=self.id,
            severity=Severity.HIGH,
            cvss=8.6,
            title="resources/read accepts dangerous URI schemes (SSRF / local-file disclosure)",
            evidence={"hits": hits},
            repro="Replay any hit URI via tools/call resources/read.",
            remediation=(
                "Restrict resources/read URI schemes to a strict allowlist. For file://, "
                "constrain to specific directories the server is meant to expose. For "
                "http(s)://, block link-local (169.254.0.0/16), loopback, and cloud "
                "metadata addresses (169.254.169.254, metadata.google.internal). Resolve "
                "DNS once and verify the resolved IP is in the allowed set."
            ),
        )
