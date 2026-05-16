from mcpmap.audit.check_ids import CHECKS, by_id, legacy_to_canonical


def test_every_legacy_id_maps_to_canonical():
    legacy = ["AUTH-001", "AUTH-002", "AUTH-003", "POISON-001", "POISON-002",
              "INJECT-001", "SSRF-001", "TRANSPORT-001", "HONEYPOT-001", "CVE-001"]
    for old in legacy:
        canon = legacy_to_canonical(old)
        assert canon is not None, f"no canonical mapping for {old}"
        rec = by_id(canon)
        assert old in rec.legacy_aliases


def test_each_canonical_check_has_cwe_and_severity_default():
    for rec in CHECKS:
        assert rec.cwe.startswith("CWE-") or rec.cwe == ""  # CVE-001 has no CWE
        assert rec.default_severity in {"info", "low", "medium", "high", "critical"}
        assert rec.canonical_id.startswith("MCP-")
