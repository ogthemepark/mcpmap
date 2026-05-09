from __future__ import annotations
import re
import uuid
import aiohttp
from mcpmap.models import Server, Tool, Finding, Severity
from mcpmap.audit.base import BaseCheck

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
    id = "INJECT-001"
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
            severity=Severity.CRITICAL,
            cvss=9.0,
            title="Command injection via tool argument (canary echo confirmed)",
            evidence={"canary": canary, "hits": hits},
            repro="Re-send the recorded payload via curl tools/call with the same arg name.",
            remediation=(
                "Never pass tool arguments to a shell. Use list-form subprocess calls "
                "(shell=False with explicit argv). For path arguments, validate against "
                "an allowlist of expected directories and reject any input containing "
                "shell metacharacters (`;`, `$`, `\\`` `, `|`, `&`, newline)."
            ),
        )
