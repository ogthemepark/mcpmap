from mcpmap.fingerprint.cves import in_range, cves_for


def test_in_range_basic():
    assert in_range("0.1.10", ">=0.0.5,<0.1.16")
    assert not in_range("0.1.16", ">=0.0.5,<0.1.16")
    assert not in_range("0.0.4", ">=0.0.5,<0.1.16")


def test_in_range_le():
    assert in_range("1.2.4", "<=1.2.4")
    assert not in_range("1.2.5", "<=1.2.4")


def test_in_range_wildcard():
    assert in_range("9.9.9", "*")


def test_cves_for_mcp_remote_old():
    cves = cves_for("mcp-remote", "0.1.10")
    assert any(c.cve == "CVE-2025-6514" for c in cves)


def test_cves_for_mcp_remote_patched():
    cves = cves_for("mcp-remote", "0.1.16")
    assert all(c.cve != "CVE-2025-6514" for c in cves)


def test_cves_for_unknown_returns_empty():
    assert cves_for("unknown", "1.0") == []
