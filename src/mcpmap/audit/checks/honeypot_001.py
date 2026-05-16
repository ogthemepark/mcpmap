from __future__ import annotations
import aiohttp
from mcpmap.models import Server, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-META-HONEYPOT")


class Honeypot001(BaseCheck):
    id = _REC.canonical_id
    intrusive = False

    async def run(self, server: Server) -> Finding | None:
        timeout = aiohttp.ClientTimeout(total=5.0)
        sids: list[str] = []
        empty_lists = 0
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
            for _ in range(3):
                try:
                    async with session.post(server.url, json=body, headers={"Accept": "application/json, text/event-stream"}) as r:
                        sid = r.headers.get("Mcp-Session-Id")
                        if sid:
                            sids.append(sid)
                        text = await r.text()
                        if '"tools": []' in text or '"tools":[]' in text:
                            empty_lists += 1
                except aiohttp.ClientError:
                    return None

        signals = []
        if len(sids) >= 2 and len(set(sids)) == 1:
            signals.append("identical Mcp-Session-Id across 3 connections")
        if empty_lists == 3:
            signals.append("tools/list always empty")
        if not signals:
            return None
        return Finding(
            check=self.id,
            aliases=list(_REC.legacy_aliases),
            severity=Severity(_REC.default_severity),
            confidence=Confidence(_REC.default_confidence),
            cwe=_REC.cwe or None,
            cvss=0.0,
            title=_REC.title,
            evidence=Evidence(
                artifacts={"signals": signals, "sample_session_ids": sids[:3]},
            ),
            repro="Reconnect 3+ times; observe identical Mcp-Session-Id and/or empty tools/list.",
        )
