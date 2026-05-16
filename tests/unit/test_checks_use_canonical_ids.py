from mcpmap.audit.check_ids import CHECKS
from mcpmap.pipeline import all_checks


def test_every_check_uses_canonical_id_and_declares_legacy_alias():
    canonical_ids = {r.canonical_id for r in CHECKS}
    seen = set()
    for chk in all_checks():
        assert chk.id in canonical_ids, f"{chk.__class__.__name__} uses non-canonical id {chk.id}"
        seen.add(chk.id)
    assert seen == canonical_ids, f"missing checks: {canonical_ids - seen}"
