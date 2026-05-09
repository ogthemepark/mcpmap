from mcpmap.models import ServerInfo
from mcpmap.fingerprint.db import load_db, match_fingerprint


def test_load_db_returns_entries():
    db = load_db()
    ids = [e["id"] for e in db]
    assert "mcp-remote" in ids
    assert "mcp-inspector" in ids


def test_match_by_server_info_substring():
    db = load_db()
    fp = match_fingerprint(ServerInfo(name="filesystem-mcp", version="1.0"), port=8000, db=db)
    assert fp == "filesystem-mcp"


def test_match_by_port_when_name_ambiguous():
    db = load_db()
    fp = match_fingerprint(ServerInfo(name="proxy", version=""), port=6277, db=db)
    assert fp == "mcp-inspector"


def test_no_match_returns_none():
    db = load_db()
    assert match_fingerprint(ServerInfo(name="totally-unknown"), port=12345, db=db) is None
