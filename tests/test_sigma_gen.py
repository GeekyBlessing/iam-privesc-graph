import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.engine.consolidation import ConsolidatedFinding
from src.engine.sigma_gen import SigmaRuleGenerator


def make_consolidated(source, technique, blast_radius, severity="CRITICAL"):
    return ConsolidatedFinding(
        finding_id="TEST-001",
        kind="direct",
        source=source,
        technique_chain=[technique],
        blast_radius=blast_radius,
        blast_radius_count=len(blast_radius),
        max_hop_count=1,
        confidence=1.0,
        risk_score=100.0,
        severity=severity,
    ) if False else ConsolidatedFinding(
        finding_id="TEST-001",
        kind="direct",
        source=source,
        technique_chain=[technique],
        blast_radius=blast_radius,
        blast_radius_count=len(blast_radius),
        max_hop_count=1,
        confidence=1.0,
        risk_score=100.0,
        severity=severity,
        description="test finding",
        remediation="test remediation",
    )


def test_rule_maps_correct_cloudtrail_event():
    gen = SigmaRuleGenerator(account_id="123456789012")
    finding = make_consolidated("roleA", "can_modify_trust", ["roleB", "roleC"])
    rule = gen.generate(finding)
    assert rule["detection"]["selection"]["eventName"] == "UpdateAssumeRolePolicy"
    assert "roleA" in rule["detection"]["selection"]["userIdentity.arn|contains"]
    print("PASS: can_modify_trust maps to UpdateAssumeRolePolicy CloudTrail event")


def test_rule_maps_correct_mitre_technique():
    gen = SigmaRuleGenerator(account_id="123456789012")
    finding = make_consolidated("roleA", "can_add_user_to_group", ["userX"])
    rule = gen.generate(finding)
    assert "attack.t1098" in rule["tags"]
    print("PASS: can_add_user_to_group tagged with MITRE T1098")


def test_severity_maps_to_sigma_level():
    gen = SigmaRuleGenerator(account_id="123456789012")
    finding = make_consolidated("roleA", "can_modify_trust", ["roleB"], severity="HIGH")
    rule = gen.generate(finding)
    assert rule["level"] == "high"
    print("PASS: HIGH severity maps to Sigma level 'high'")


def test_unknown_technique_returns_none():
    gen = SigmaRuleGenerator(account_id="123456789012")
    finding = make_consolidated("roleA", "not_a_real_technique", ["roleB"])
    rule = gen.generate(finding)
    assert rule is None
    print("PASS: unmapped technique returns None instead of a malformed rule")


if __name__ == "__main__":
    test_rule_maps_correct_cloudtrail_event()
    test_rule_maps_correct_mitre_technique()
    test_severity_maps_to_sigma_level()
    test_unknown_technique_returns_none()
    print("\nAll Sigma generation tests passed.")
