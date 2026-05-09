from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Target(BaseModel):
    host: str
    port: int
    path_hint: str | None = None
    source: str = "active"  # active|shodan|config|file

    def url(self, scheme: str = "http", path: str = "/") -> str:
        return f"{scheme}://{self.host}:{self.port}{path}"


class Tool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict, alias="inputSchema")


class ServerInfo(BaseModel):
    name: str = ""
    version: str = ""


class Server(BaseModel):
    url: str
    transport: str = "unknown"  # streamable-http | http+sse | stdio | unknown
    server_info: ServerInfo = Field(default_factory=ServerInfo)
    fingerprint_id: str | None = None
    protocol_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    tools: list[Tool] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    instructions: str = ""
    framework: str | None = None
    raw_response_excerpt: str = ""


class Finding(BaseModel):
    check: str
    severity: Severity
    title: str
    cvss: float | None = None
    cve: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    repro: str = ""


class ScanConfig(BaseModel):
    passive: bool = False
    rate_rps: int = 10


class ScanResult(BaseModel):
    schema_version: str = "1.0"
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    config: ScanConfig = Field(default_factory=ScanConfig)
    servers: list[Server] = Field(default_factory=list)
    findings: dict[str, list[Finding]] = Field(default_factory=dict)  # url -> findings[]
