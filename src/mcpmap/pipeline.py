from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone
from ipaddress import ip_network
import aiohttp
from mcpmap.models import Target, Server, ServerInfo, Tool, ScanResult, ScanConfig
from mcpmap.discover.active import active_discover, PRIORITY_PORTS
from mcpmap.discover.shodan_source import shodan_targets
from mcpmap.discover.handshake import initialize
from mcpmap.fingerprint.db import match_fingerprint
from mcpmap.audit.runner import run_checks
from mcpmap.audit.checks.auth_001 import Auth001UnauthToolsList
from mcpmap.audit.checks.auth_002 import Auth002AudienceBinding
from mcpmap.audit.checks.auth_003 import Auth003OriginValidation
from mcpmap.audit.checks.poison_001 import Poison001ToolDescriptionRegex
from mcpmap.audit.checks.poison_002 import Poison002UnicodeTags
from mcpmap.audit.checks.inject_001 import Inject001CanaryEcho
from mcpmap.audit.checks.ssrf_001 import Ssrf001ResourcesRead
from mcpmap.audit.checks.transport_001 import Transport001LegacySse
from mcpmap.audit.checks.honeypot_001 import Honeypot001
from mcpmap.audit.checks.cve_001 import Cve001VersionMatch


def all_checks():
    return [
        Auth001UnauthToolsList(), Auth002AudienceBinding(), Auth003OriginValidation(),
        Poison001ToolDescriptionRegex(), Poison002UnicodeTags(),
        Inject001CanaryEcho(), Ssrf001ResourcesRead(),
        Transport001LegacySse(), Honeypot001(), Cve001VersionMatch(),
    ]


def _parse_target(target: str) -> tuple[str, list[str]]:
    """Return (kind, items). kind in {host, cidr, url, file, shodan}."""
    if target.startswith("shodan:"):
        return "shodan", [target[len("shodan:"):]]
    if target.startswith("file:"):
        return "file", [target[len("file:"):]]
    if target.startswith("http://") or target.startswith("https://"):
        return "url", [target]
    if "/" in target:
        try:
            ip_network(target, strict=False)
            return "cidr", [target]
        except ValueError:
            pass
    return "host", [target]


def _expand_cidr(cidr: str) -> list[str]:
    return [str(ip) for ip in ip_network(cidr, strict=False).hosts()]


async def _enrich_target(t: Target) -> Server | None:
    scheme = "https" if t.port in (443, 8443) else "http"
    path = t.path_hint or "/mcp"
    url = f"{scheme}://{t.host}:{t.port}{path}"
    res = await initialize(url)
    if not res:
        return None
    info = ServerInfo(**(res.get("serverInfo") or {}))
    detected_transport = res.pop("_mcpmap_transport", "streamable-http")
    server = Server(
        url=url,
        server_info=info,
        capabilities=res.get("capabilities", {}),
        protocol_version=res.get("protocolVersion"),
        transport=detected_transport,
    )
    server.fingerprint_id = match_fingerprint(info, port=t.port)
    timeout = aiohttp.ClientTimeout(total=5.0)
    async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=False)) as sess:
        try:
            async with sess.post(url, json={"jsonrpc":"2.0","id":1,"method":"tools/list"}, headers={"Accept":"application/json, text/event-stream"}) as r:
                data = await r.json(content_type=None)
                server.tools = [Tool(**tool) for tool in data.get("result", {}).get("tools", [])]
        except Exception:
            pass
    return server


async def run_scan(target: str, passive: bool = False, rate: int = 10) -> ScanResult:
    kind, items = _parse_target(target)
    targets: list[Target] = []
    if kind == "host":
        targets.extend(await active_discover(items[0], ports=PRIORITY_PORTS))
    elif kind == "cidr":
        for host in _expand_cidr(items[0]):
            targets.extend(await active_discover(host, ports=PRIORITY_PORTS))
    elif kind == "url":
        from urllib.parse import urlparse
        u = urlparse(items[0])
        port = u.port or (443 if u.scheme == "https" else 80)
        targets.append(Target(host=u.hostname, port=port, path_hint=u.path or "/mcp", source="url"))
    elif kind == "shodan":
        st = shodan_targets(queries=[items[0]])
        verified: list[Target] = []
        for t in st:
            verified.extend(await active_discover(t.host, ports=[t.port]))
        targets = verified
    elif kind == "file":
        from pathlib import Path
        for line in Path(items[0]).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sub = await run_scan(line, passive=passive, rate=rate)
            for s in sub.servers:
                from urllib.parse import urlparse
                u = urlparse(s.url)
                targets.append(Target(host=u.hostname, port=u.port or 80, path_hint=u.path))

    servers: list[Server] = []
    findings: dict[str, list] = {}
    for t in targets:
        srv = await _enrich_target(t)
        if not srv:
            continue
        servers.append(srv)
        findings[srv.url] = await run_checks(srv, all_checks(), passive=passive)

    return ScanResult(
        scan_id=f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}",
        config=ScanConfig(passive=passive, rate_rps=rate),
        servers=servers,
        findings=findings,
    )
