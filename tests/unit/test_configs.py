from pathlib import Path
from mcpmap.discover.configs import parse_config

FIX = Path(__file__).parent.parent / "fixtures"


def test_parse_claude_desktop_config():
    entries = parse_config(FIX / "claude_desktop_config.json")
    assert len(entries) == 2
    fs = next(e for e in entries if e.name == "filesystem")
    assert fs.command == "npx"
    assert "@modelcontextprotocol/server-filesystem" in fs.args
    pinned = next(e for e in entries if e.name == "remote-pinned")
    assert "mcp-remote@0.1.10" in pinned.args


def test_parse_missing_file_returns_empty(tmp_path):
    assert parse_config(tmp_path / "nope.json") == []
