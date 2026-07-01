"""
Evaluates effective IAM permissions honoring full AWS precedence:
explicit Deny > SCP boundary > permission boundary > identity policy > resource policy.
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""
from dataclasses import dataclass
from .models import PolicyStatement, PolicyEffect, ConditionBlock


@dataclass
class EvaluationResult:
    allowed: bool
    reason: str
    confidence: float
    governing_statements: list[PolicyStatement]


class PolicyEvaluator:
    def __init__(self):
        pass

    def evaluate_action(
        self,
        action: str,
        identity_statements: list[PolicyStatement],
        scp_statements: list[PolicyStatement] | None = None,
        boundary_statements: list[PolicyStatement] | None = None,
        resource_statements: list[PolicyStatement] | None = None,
    ) -> EvaluationResult:
        scp_statements = scp_statements or []
        boundary_statements = boundary_statements or []
        resource_statements = resource_statements or []

        # 1. Explicit deny anywhere wins immediately
        for layer_name, layer in [
            ("SCP", scp_statements),
            ("permission_boundary", boundary_statements),
            ("identity_policy", identity_statements),
            ("resource_policy", resource_statements),
        ]:
            for stmt in layer:
                if stmt.effect == PolicyEffect.DENY and self._matches_action(action, stmt.actions):
                    return EvaluationResult(
                        allowed=False,
                        reason=f"Explicit deny in {layer_name}",
                        confidence=1.0,
                        governing_statements=[stmt],
                    )

        # 2. SCP must allow (if org SCPs are in scope) — SCPs are a ceiling, not a grant
        if scp_statements:
            if not self._has_allow(action, scp_statements):
                return EvaluationResult(
                    allowed=False,
                    reason="Not permitted by SCP ceiling",
                    confidence=1.0,
                    governing_statements=[],
                )

        # 3. Permission boundary must allow (if set) — also a ceiling, not a grant
        if boundary_statements:
            if not self._has_allow(action, boundary_statements):
                return EvaluationResult(
                    allowed=False,
                    reason="Not permitted by permission boundary",
                    confidence=1.0,
                    governing_statements=[],
                )

        # 4. Identity policy OR resource policy must grant Allow
        identity_allow = [s for s in identity_statements
                           if s.effect == PolicyEffect.ALLOW and self._matches_action(action, s.actions)]
        resource_allow = [s for s in resource_statements
                           if s.effect == PolicyEffect.ALLOW and self._matches_action(action, s.actions)]

        governing = identity_allow + resource_allow
        if not governing:
            return EvaluationResult(
                allowed=False,
                reason="No Allow statement grants this action",
                confidence=1.0,
                governing_statements=[],
            )

        # 5. Confidence scoring — restrictive conditions lower exploitability confidence
        confidence = 1.0
        for stmt in governing:
            if stmt.condition.has_restrictive_conditions():
                confidence = min(confidence, 0.4)

        return EvaluationResult(
            allowed=True,
            reason="Allowed via " + ", ".join(
                s.source_policy_type or "unknown" for s in governing
            ),
            confidence=confidence,
            governing_statements=governing,
        )

    @staticmethod
    def _matches_action(action: str, action_patterns: list[str]) -> bool:
        """Handles IAM wildcard matching, e.g. iam:* or iam:Create*."""
        import fnmatch
        return any(fnmatch.fnmatch(action.lower(), pat.lower()) for pat in action_patterns)

    @staticmethod
    def _has_allow(action: str, statements: list[PolicyStatement]) -> bool:
        return any(
            s.effect == PolicyEffect.ALLOW and PolicyEvaluator._matches_action(action, s.actions)
            for s in statements
        )
