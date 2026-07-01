import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.engine.scoring import Finding
from src.engine.consolidation import consolidate


def make_finding(source, target, technique_chain, hop_count, risk_score=90.0, severity="CRITICAL"):
    return Finding(
        finding_id="TEST",
        source=source,
        target=target,
        technique_chain=technique_chain,
        hop_count=hop_count,
        confidence=1.0,
        risk_score=risk_score,
        severity=severity,
        target_is_high_value=False,
        description="test",
        remediation="test remediation",
    )


def test_direct_findings_group_by_source_and_technique():
    findings = [
        make_finding("roleA", "roleB", ["can_modify_trust"], 1),
        make_finding("roleA", "roleC", ["can_modify_trust"], 1),
        make_finding("roleA", "roleD", ["can_modify_trust"], 1),
    ]
    result = consolidate(findings)
    assert len(result) == 1
    assert result[0].kind == "direct"
    assert result[0].blast_radius_count == 3
    print("PASS: direct findings consolidate to one root cause with blast radius 3")


def test_direct_findings_do_not_mix_target_types():
    # can_add_user_to_group should never appear grouped with can_modify_trust,
    # even if same source -- this is the bug we caught earlier in the session
    findings = [
        make_finding("roleA", "userX", ["can_add_user_to_group"], 1),
        make_finding("roleA", "roleB", ["can_modify_trust"], 1),
    ]
    result = consolidate(findings)
    assert len(result) == 2
    techniques = {tuple(f.technique_chain) for f in result}
    assert ("can_add_user_to_group",) in techniques
    assert ("can_modify_trust",) in techniques
    print("PASS: different techniques from same source stay as separate findings")


def test_chained_findings_kept_separate_from_direct():
    findings = [
        make_finding("roleA", "roleB", ["can_modify_trust"], 1),
        make_finding("roleA", "roleC", ["can_modify_trust", "can_modify_trust"], 2),
    ]
    result = consolidate(findings)
    kinds = {f.kind for f in result}
    assert kinds == {"direct", "chained"}
    print("PASS: chained multi-hop findings are not collapsed into direct findings")


def test_chained_findings_with_different_sequences_not_merged():
    findings = [
        make_finding("roleA", "roleX", ["can_modify_trust", "can_modify_trust"], 2),
        make_finding("roleA", "roleY", ["can_add_user_to_group", "can_modify_trust"], 2),
    ]
    result = consolidate(findings)
    chained = [f for f in result if f.kind == "chained"]
    assert len(chained) == 2
    print("PASS: distinct technique sequences produce distinct chained findings")


if __name__ == "__main__":
    test_direct_findings_group_by_source_and_technique()
    test_direct_findings_do_not_mix_target_types()
    test_chained_findings_kept_separate_from_direct()
    test_chained_findings_with_different_sequences_not_merged()
    print("\nAll consolidation tests passed.")
