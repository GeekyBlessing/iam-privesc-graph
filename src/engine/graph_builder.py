"""
Builds the IAM graph from a live AWS account.
Pulls users, roles, groups, and their attached/inline policies,
then wires edges (CAN_ASSUME, CAN_PASS_ROLE, etc.) using PolicyEvaluator.
"""
import json
import fnmatch
import boto3
import networkx as nx
from .models import (
    GraphNode, GraphEdge, NodeType, EdgeType,
    PolicyStatement, PolicyEffect, ConditionBlock,
)
from .policy_evaluator import PolicyEvaluator

ESCALATION_ACTIONS = [
    "sts:AssumeRole",
    "iam:PassRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
    "iam:CreateLoginProfile",
]

# Actions that grant control over a TARGET principal (edges resolved per-target,
# not self-referential). Maps action -> which node types it can target.
TARGETED_ACTIONS = {
    "iam:AttachUserPolicy": [NodeType.USER],
    "iam:AttachRolePolicy": [NodeType.ROLE],
    "iam:PutUserPolicy": [NodeType.USER],
    "iam:PutRolePolicy": [NodeType.ROLE],
    "iam:UpdateAssumeRolePolicy": [NodeType.ROLE],
    "iam:AddUserToGroup": [NodeType.USER],
    "iam:CreateAccessKey": [NodeType.USER],
    "iam:UpdateLoginProfile": [NodeType.USER],
}

SERVICE_LINKED_PREFIXES = ("aws-service-role/",)
SERVICE_LINKED_NAME_PREFIXES = ("AWSServiceRoleFor",)


class IAMGraphBuilder:
    def __init__(self, session: boto3.Session = None, region: str = "eu-north-1"):
        self.session = session or boto3.Session(region_name=region)
        self.iam = self.session.client("iam")
        self.evaluator = PolicyEvaluator()
        self.graph = nx.DiGraph()

    def build(self) -> nx.DiGraph:
        print("[*] Fetching IAM users...")
        users = self._get_users()
        print(f"[+] Found {len(users)} users")

        print("[*] Fetching IAM roles...")
        all_roles = self._get_roles()
        roles = [r for r in all_roles if not self._is_service_linked(r)]
        print(f"[+] Found {len(all_roles)} roles ({len(roles)} attacker-relevant, "
              f"{len(all_roles) - len(roles)} AWS service-linked filtered out)")

        print("[*] Fetching IAM groups...")
        groups = self._get_groups()
        print(f"[+] Found {len(groups)} groups")

        all_principals = users + roles + groups  # service-linked roles excluded from graph

        for p in all_principals:
            self.graph.add_node(p.node_id, node=p)

        for principal in users + roles:
            statements = self._get_effective_statements(principal)
            self._add_escalation_edges(principal, statements, all_principals)

        print(f"[+] Graph built: {self.graph.number_of_nodes()} nodes, "
              f"{self.graph.number_of_edges()} edges")
        return self.graph

    @staticmethod
    def _is_service_linked(role: GraphNode) -> bool:
        path = role.metadata.get("path", "")
        return (any(path.startswith(p) for p in SERVICE_LINKED_PREFIXES) or
                any(role.name.startswith(p) for p in SERVICE_LINKED_NAME_PREFIXES))

    # ---------- AWS data collection ----------

    def _get_users(self) -> list[GraphNode]:
        nodes = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                nodes.append(GraphNode(
                    node_id=u["Arn"],
                    node_type=NodeType.USER,
                    name=u["UserName"],
                    permission_boundary_arn=u.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                    is_human=True,
                ))
        return nodes

    def _get_roles(self) -> list[GraphNode]:
        nodes = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page["Roles"]:
                is_service_role = "service-role" in r.get("Path", "") or \
                    r["RoleName"].startswith(SERVICE_LINKED_NAME_PREFIXES)
                nodes.append(GraphNode(
                    node_id=r["Arn"],
                    node_type=NodeType.ROLE,
                    name=r["RoleName"],
                    permission_boundary_arn=r.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                    is_human=not is_service_role,
                    metadata={
                        "trust_policy": r.get("AssumeRolePolicyDocument", {}),
                        "path": r.get("Path", ""),
                    },
                ))
        return nodes

    def _get_groups(self) -> list[GraphNode]:
        nodes = []
        paginator = self.iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page["Groups"]:
                nodes.append(GraphNode(
                    node_id=g["Arn"],
                    node_type=NodeType.GROUP,
                    name=g["GroupName"],
                ))
        return nodes

    def _get_effective_statements(self, principal: GraphNode) -> list[PolicyStatement]:
        statements = []
        name = principal.name
        is_role = principal.node_type == NodeType.ROLE

        try:
            if is_role:
                attached = self.iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
                inline_names = self.iam.list_role_policies(RoleName=name)["PolicyNames"]
            else:
                attached = self.iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
                inline_names = self.iam.list_user_policies(UserName=name)["PolicyNames"]
        except self.iam.exceptions.NoSuchEntityException:
            return statements

        for pol in attached:
            doc = self._get_policy_document(pol["PolicyArn"])
            statements.extend(self._parse_statements(doc, pol["PolicyArn"], "identity"))

        for pname in inline_names:
            if is_role:
                doc = self.iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
            else:
                doc = self.iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
            statements.extend(self._parse_statements(doc, f"inline:{pname}", "identity"))

        return statements

    def _get_policy_document(self, policy_arn: str) -> dict:
        pol = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = pol["DefaultVersionId"]
        version = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return version["PolicyVersion"]["Document"]

    @staticmethod
    def _parse_statements(doc: dict, source_arn: str, source_type: str) -> list[PolicyStatement]:
        results = []
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for s in stmts:
            effect = PolicyEffect.ALLOW if s.get("Effect") == "Allow" else PolicyEffect.DENY
            actions = s.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = s.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
            results.append(PolicyStatement(
                effect=effect,
                actions=actions,
                resources=resources,
                condition=ConditionBlock(raw=s.get("Condition", {})),
                source_policy_arn=source_arn,
                source_policy_type=source_type,
            ))
        return results

    # ---------- Edge derivation ----------

    def _add_escalation_edges(self, principal: GraphNode, statements: list[PolicyStatement],
                                all_principals: list[GraphNode]):
        for action in ESCALATION_ACTIONS:
            result = self.evaluator.evaluate_action(action, identity_statements=statements)
            if not result.allowed:
                continue

            edge_type = self._action_to_edge_type(action)
            if edge_type is None:
                continue

            if action == "sts:AssumeRole":
                for target in all_principals:
                    if target.node_type == NodeType.ROLE and self._trust_allows(target, principal):
                        self._add_edge(principal, target, edge_type, result.governing_statements, result.confidence)

            elif action in TARGETED_ACTIONS:
                # Resource-scoped check: does the governing statement's Resource
                # actually cover this target's ARN (or is it "*")?
                allowed_types = TARGETED_ACTIONS[action]
                resource_patterns = self._collect_resources(result.governing_statements)
                for target in all_principals:
                    if target.node_type not in allowed_types:
                        continue
                    if target.node_id == principal.node_id:
                        continue  # skip self, not interesting for escalation
                    if self._resource_matches(target.node_id, resource_patterns):
                        self._add_edge(principal, target, edge_type, result.governing_statements, result.confidence)

            else:
                # e.g. CreatePolicyVersion, SetDefaultPolicyVersion — self-capability,
                # kept as self-edge since it modifies the principal's own attached policy
                self._add_edge(principal, principal, edge_type, result.governing_statements, result.confidence)

    @staticmethod
    def _collect_resources(statements: list[PolicyStatement]) -> list[str]:
        patterns = []
        for s in statements:
            patterns.extend(s.resources)
        return patterns or ["*"]

    @staticmethod
    def _resource_matches(target_arn: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(target_arn, pat) for pat in patterns)

    def _trust_allows(self, role: GraphNode, principal: GraphNode) -> bool:
        """Checks if role's trust policy names this principal's ARN or account root."""
        trust_doc = role.metadata.get("trust_policy", {})
        stmts = trust_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            principal_block = stmt.get("Principal", {})
            aws_principals = principal_block.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if p == principal.node_id:
                    return True
                if p.endswith(":root") and p.split(":")[4] == principal.node_id.split(":")[4]:
                    return True  # account-root trust covers all principals in that account
        return False

    @staticmethod
    def _action_to_edge_type(action: str) -> EdgeType | None:
        mapping = {
            "sts:AssumeRole": EdgeType.CAN_ASSUME,
            "iam:PassRole": EdgeType.CAN_PASS_ROLE,
            "iam:AttachUserPolicy": EdgeType.CAN_ATTACH_POLICY,
            "iam:AttachRolePolicy": EdgeType.CAN_ATTACH_POLICY,
            "iam:CreatePolicyVersion": EdgeType.CAN_CREATE_POLICY_VERSION,
            "iam:UpdateAssumeRolePolicy": EdgeType.CAN_MODIFY_TRUST,
            "iam:AddUserToGroup": EdgeType.CAN_ADD_USER_TO_GROUP,
        }
        return mapping.get(action)

    def _add_edge(self, source: GraphNode, target: GraphNode, edge_type: EdgeType,
                  statements: list[PolicyStatement], confidence: float):
        self.graph.add_edge(
            source.node_id, target.node_id,
            edge=GraphEdge(
                source_id=source.node_id,
                target_id=target.node_id,
                edge_type=edge_type,
                evidence=statements,
                confidence=confidence,
            )
        )
