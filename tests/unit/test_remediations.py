from mcpmap.audit.remediations import lookup, all_remediations  # noqa: F401
from mcpmap.audit.check_ids import CHECKS


def test_every_canonical_check_has_a_remediation_entry():
    for rec in CHECKS:
        rem = lookup(rec.canonical_id)
        assert rem is not None, f"missing remediation for {rec.canonical_id}"
        assert rem.summary
        assert isinstance(rem.references, list)


def test_lookup_accepts_legacy_id():
    rem = lookup("AUTH-001")
    assert rem is not None and rem.summary
