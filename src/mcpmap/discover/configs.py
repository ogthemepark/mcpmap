from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from pydantic import BaseModel, Field


class ConfigEntry(BaseModel):
    name: str
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    source_path: str = ""


def _config_paths() -> list[Path]:
    """OS-specific candidate config paths to scan when --paths auto."""
    home = Path.home()
    paths = [
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp.json",
        home / ".config" / "claude-code" / "mcp_settings.json",
        Path.cwd() / ".vscode" / "mcp.json",
    ]
    if sys.platform == "darwin":
        paths.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    paths.extend((home / ".gemini" / "extensions").glob("*/mcp.json")) if (home / ".gemini" / "extensions").exists() else None
    return paths


def parse_config(path: Path) -> list[ConfigEntry]:
    """Parse a single MCP host config file. Tolerates missing files."""
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    servers = raw.get("mcpServers") or raw.get("servers") or {}
    out: list[ConfigEntry] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append(ConfigEntry(
            name=name,
            command=cfg.get("command", ""),
            args=list(cfg.get("args", [])),
            env=dict(cfg.get("env", {})),
            source_path=str(path),
        ))
    return out


def discover_configs(paths: list[Path] | None = None) -> list[ConfigEntry]:
    """Walk all known host-config locations and return parsed entries."""
    paths = paths or _config_paths()
    entries: list[ConfigEntry] = []
    for p in paths:
        entries.extend(parse_config(p))
    return entries
