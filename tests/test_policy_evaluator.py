import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.engine.policy_evaluator import PolicyEvaluator
from src.engine.models import PolicyStatement, PolicyEffect, ConditionBlock

def test_basic_allow():
    ev = PolicyEvaluator()
    stmt = PolicyStatement(
        effect=PolicyEffect.ALLOW,
        actions=["iam:PassRole"],
        resources=["*"],
        source_policy_type="identity",
    )
    result = ev.evaluate_action("iam:PassRole", identity_statements=[stmt])
    assert result.allowed is True
    print("PASS: basic allow ->", result.reason)

def test_explicit_deny_wins():
    ev = PolicyEvaluator()
    allow_stmt = PolicyStatement(PolicyEffect.ALLOW, ["iam:*"], ["*"], source_policy_type="identity")
    deny_stmt = PolicyStatement(PolicyEffect.DENY, ["iam:PassRole"], ["*"], source_policy_type="SCP")
    result = ev.evaluate_action("iam:PassRole", identity_statements=[allow_stmt], scp_statements=[deny_stmt])
    assert result.allowed is False
    print("PASS: explicit deny wins ->", result.reason)

def test_condition_lowers_confidence():
    ev = PolicyEvaluator()
    stmt = PolicyStatement(
        effect=PolicyEffect.ALLOW,
        actions=["sts:AssumeRole"],
        resources=["*"],
        condition=ConditionBlock(raw={"aws:MultiFactorAuthPresent": "true"}),
        source_policy_type="identity",
    )
    result = ev.evaluate_action("sts:AssumeRole", identity_statements=[stmt])
    assert result.allowed is True
    assert result.confidence < 1.0
    print("PASS: MFA condition lowers confidence ->", result.confidence)

if __name__ == "__main__":
    test_basic_allow()
    test_explicit_deny_wins()
    test_condition_lowers_confidence()
    print("\nAll tests passed.")
