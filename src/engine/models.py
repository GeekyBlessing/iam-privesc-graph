"""
Core data models for the IAM privilege escalation graph engine.
Nodes = IAM principals/resources. Edges = control relationships.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(Enum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    POLICY = "policy"
    RESOURCE = "resource"  # e.g. Lambda function, EC2 instance


class EdgeType(Enum):
    CAN_ASSUME = "can_assume"              # sts:AssumeRole
    CAN_PASS_ROLE = "can_pass_role"        # iam:PassRole -> service action
    CAN_ATTACH_POLICY = "can_attach_policy"
    CAN_MODIFY_TRUST = "can_modify_trust"  # iam:UpdateAssumeRolePolicy
    CAN_CREATE_POLICY_VERSION = "can_create_policy_version"
    CAN_ADD_USER_TO_GROUP = "can_add_user_to_group"
    MEMBER_OF = "member_of"                # user -> group
    HAS_POLICY = "has_policy"              # principal -> attached policy


class PolicyEffect(Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass
class ConditionBlock:
    """Represents IAM policy Condition keys attached to a statement."""
    raw: dict = field(default_factory=dict)

    def has_restrictive_conditions(self) -> bool:
        """
        Conservative check: known-strict condition keys that meaningfully
        narrow exploitability (MFA, source IP, org ID, external ID).
        """
        strict_keys = {
            "aws:MultiFactorAuthPresent",
            "aws:SourceIp",
            "aws:PrincipalOrgID",
            "sts:ExternalId",
            "aws:SourceVpce",
        }
        return any(k in self.raw for k in strict_keys)


@dataclass
class PolicyStatement:
    effect: PolicyEffect
    actions: list[str]
    resources: list[str]
    condition: ConditionBlock = field(default_factory=ConditionBlock)
    source_policy_arn: Optional[str] = None
    source_policy_type: Optional[str] = None  # "identity" | "resource" | "scp" | "boundary"


@dataclass
class GraphNode:
    node_id: str            # ARN
    node_type: NodeType
    name: str
    permission_boundary_arn: Optional[str] = None
    is_human: bool = True    # heuristic: user vs service role
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    condition: ConditionBlock = field(default_factory=ConditionBlock)
    evidence: list[PolicyStatement] = field(default_factory=list)  # what granted this edge
    confidence: float = 1.0  # lowered if conditions restrict exploitability
