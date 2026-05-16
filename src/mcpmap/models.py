from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Evidence(BaseModel):
    """Typed evidence container. All fields optional. Use `artifacts` for ad-hoc data
    that doesn't fit the named slots — keeps the wire format introspectable while
    allowing checks to attach idiosyncratic detail."""
    request: dict[str, Any] | None = None
    response_status: int | None = None
    response_excerpt: str | None = None
    matched_patterns: list[str] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_legacy(cls, raw: dict[str, Any] | "Evidence" | None) -> "Evidence":
        if raw is None:
            return cls()
        if isinstance(raw, cls):
            return raw
        # Copy first to avoid mutating the caller's dict
        raw = dict(raw)
        named: dict[str, Any] = {}
        # Pull known keys into named slots only when the value matches the expected type;
        # otherwise leave them to fall through to artifacts so legacy callers don't break.
        if "request" in raw and isinstance(raw["request"], dict):
            named["request"] = raw.pop("request")
        if "response_status" in raw and isinstance(raw["response_status"], int):
            named["response_status"] = raw.pop("response_status")
        if "response_excerpt" in raw and isinstance(raw["response_excerpt"], str):
            named["response_excerpt"] = raw.pop("response_excerpt")
        if "matched_patterns" in raw and isinstance(raw["matched_patterns"], list):
            named["matched_patterns"] = raw.pop("matched_patterns")
        return cls(**named, artifacts=raw)


class Target(BaseModel):
    host: str
    port: int
    path_hint: str | None = None
    source: str = "active"  # active|shodan|config|file

    def url(self, scheme: str = "http", path: str = "/") -> str:
        return f"{scheme}://{self.host}:{self.port}{path}"


class Tool(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

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
    check: str                                   # canonical check ID, e.g. MCP-AUTH-UNAUTH-LIST
    aliases: list[str] = Field(default_factory=list)  # e.g. ["AUTH-001"] for back-compat
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    title: str
    cvss: float | None = None
    cvss_vector: str | None = None              # full CVSS 3.1 vector string
    cve: str | None = None
    cwe: str | None = None                       # e.g. "CWE-306"
    evidence: Evidence = Field(default_factory=Evidence)
    repro: str = ""
    remediation: str | None = None              # set by renderer from data/remediations.yaml; checks leave None
    related_to: str | None = None               # check ID of the parent finding (set by correlator)

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v):
        return Evidence.from_legacy(v) if not isinstance(v, Evidence) else v


class ScanConfig(BaseModel):
    passive: bool = False
    rate_rps: int = 10


class ScanResult(BaseModel):
    schema_version: str = "1.1"
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    config: ScanConfig = Field(default_factory=ScanConfig)
    servers: list[Server] = Field(default_factory=list)
    findings: dict[str, list[Finding]] = Field(default_factory=dict)  # url -> findings[]
