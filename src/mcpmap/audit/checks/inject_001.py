from __future__ import annotations
import re
import uuid
import aiohttp
from mcpmap.models import Server, Tool, Finding, Severity, Confidence, Evidence
from mcpmap.audit.base import BaseCheck
from mcpmap.audit.check_ids import by_id

_REC = by_id("MCP-TOOL-CMD-INJECT")

HINT_RE = re.compile(r"\b(command|cmd|exec|shell|file|filename|path|url|endpoint|webhook|uri)\b", re.I)


def _candidate_string_args(tool: Tool) -> list[str]:
    schema = tool.input_schema or {}
    props = schema.get("properties", {})
    out: list[str] = []
    for name, spec in props.items():
        if not isinstance(spec, dict):
            continue
        if spec.get("type") != "string":
            continue
        desc = (spec.get("description") or "") + " " + name
        if HINT_RE.search(desc):
            out.append(name)
    return out


def _payloads(canary: str) -> list[str]:
    return [
        f"; echo {canary}",
        f"$(echo {canary})",
        f"`echo {canary}`",
        f"\necho {canary}",
    ]


class Inject001CanaryEcho(BaseCheck):
    id = _REC.canonical_id
    intrusive = True

    async def run(self, server: Server) -> Finding | None:
        timeout = aiohttp.ClientTimeout(total=10.0)
        canary = f"MCPMAP_CANARY_{uuid.uuid4().hex}"
        hits: list[dict] = []
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
            for tool in server.tools:
                arg_names = _candidate_string_args(tool)
                if not arg_names:
                    continue
                for arg_name in arg_names:
                    for payload in _payloads(canary):
                        body = {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": tool.name, "arguments": {arg_name: payload}},
                        }
                        try:
                            async with session.post(server.url, json=body, headers={"Accept": "application/json, text/event-stream"}) as r:
                                text = await r.text()
                        except aiohttp.ClientError:
                            continue
                        if canary in text:
                            hits.append({"tool": tool.name, "arg": arg_name, "payload": payload, "response_excerpt": text[:512]})
                            break
                    if hits and hits[-1]["tool"] == tool.name:
                        break

        if not hits:
            return None
        return Finding(
            check=self.id,
            aliases=list(_REC.legacy_aliases),
            severity=Severity(_REC.default_severity),
            confidence=Confidence(_REC.default_confidence),
            cwe=_REC.cwe or None,
            cvss=9.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            title=_REC.title,
            evidence=Evidence(
                artifacts={"canary": canary, "hits": hits},
            ),
            repro="Re-send the recorded payload via curl tools/call with the same arg name.",
        )
