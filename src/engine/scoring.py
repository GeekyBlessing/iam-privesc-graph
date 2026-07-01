"""
Risk scoring and report generation for discovered escalation paths.
Collapses raw path permutations into deduplicated, prioritized findings,
scored using a weighted model similar to CloudSentinel's approach:
  - Target value (does the path reach a high-privilege / admin-equivalent node?)
  - Path confidence (weakest-link, already computed — condition-key aware)
  - Path length (shorter = more directly exploitable)
  - Principal type (human-controlled source is more exploitable than deep service chains)
"""
import json
import datetime
from dataclasses import dataclass, asdict
from .traversal import EscalationPath
from .models import GraphNode, NodeType


ADMIN_ACTION_MARKERS = {"iam:*", "*", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
                         "iam:PutRolePolicy", "iam:PutUserPolicy"}


@dataclass
class Finding:
    finding_id: str
    source: str
    target: str
    technique_chain: list[str]
    hop_count: int
    confidence: float
    risk_score: float
    severity: str
    target_is_high_value: bool
    description: str
    remediation: str


class RiskScorer:
    def __init__(self, graph, high_value_node_ids: set[str] | None = None):
        self.graph = graph
        self.high_value_node_ids = high_value_node_ids or set()

    def build_findings(self, paths: list[EscalationPath]) -> list[Finding]:
        # Dedupe: collapse to unique (source, target, technique_chain) triples —
        # this removes the permutation noise seen in raw path enumeration
        seen = set()
        findings = []

        for p in paths:
            source = p.hops[0]
            target = p.hops[-1]
            key = (source, target, tuple(p.edge_types))
            if key in seen:
                continue
            seen.add(key)

            score, severity = self._score(p, target)
            findings.append(Finding(
                finding_id=f"PRIVESC-{len(findings)+1:03d}",
                source=self._short(source),
                target=self._short(target),
                technique_chain=p.edge_types,
                hop_count=p.length,
                confidence=round(p.confidence, 2),
                risk_score=round(score, 1),
                severity=severity,
                target_is_high_value=target in self.high_value_node_ids,
                description=self._describe(p),
                remediation=self._remediate(p),
            ))

        findings.sort(key=lambda f: -f.risk_score)
        return findings

    def _score(self, path: EscalationPath, target: str) -> tuple[float, str]:
        # Base score 0-100, weighted like CloudSentinel's model
        base = 40.0

        # Shorter paths are more directly exploitable
        base += max(0, (4 - path.length)) * 10

        # High confidence (no restrictive conditions) raises risk
        base += path.confidence * 20

        # Target value: reaching a high-value/admin node is the biggest multiplier
        if target in self.high_value_node_ids:
            base += 25
        elif self._touches_iam_control(path):
            base += 15

        base = min(base, 100.0)

        if base >= 85:
            severity = "CRITICAL"
        elif base >= 65:
            severity = "HIGH"
        elif base >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return base, severity

    @staticmethod
    def _touches_iam_control(path: EscalationPath) -> bool:
        iam_control_edges = {"can_modify_trust", "can_attach_policy",
                              "can_create_policy_version", "can_add_user_to_group"}
        return any(e in iam_control_edges for e in path.edge_types)

    @staticmethod
    def _short(arn: str) -> str:
        return arn.split("/")[-1]

    def _describe(self, path: EscalationPath) -> str:
        chain = " -> ".join(
            f"{self._short(path.hops[i])} [{path.edge_types[i]}]"
            for i in range(len(path.hops) - 1)
        ) + f" -> {self._short(path.hops[-1])}"
        return f"Escalation chain: {chain}"

    @staticmethod
    def _remediate(path: EscalationPath) -> str:
        techniques = set(path.edge_types)
        tips = []
        if "can_modify_trust" in techniques:
            tips.append("Scope iam:UpdateAssumeRolePolicy to specific role ARNs instead of '*'")
        if "can_add_user_to_group" in techniques:
            tips.append("Restrict iam:AddUserToGroup to specific group ARNs and require MFA condition")
        if "can_attach_policy" in techniques:
            tips.append("Remove iam:Attach*Policy from non-admin roles or scope to specific policy ARNs")
        if "can_create_policy_version" in techniques:
            tips.append("Restrict iam:CreatePolicyVersion to prevent self-privilege modification")
        if "can_pass_role" in techniques:
            tips.append("Scope iam:PassRole with iam:PassedToService condition key")
        if not tips:
            tips.append("Review and scope down the permissions enabling this chain")
        return "; ".join(tips)


class ReportBuilder:
    def __init__(self, account_id: str, region: str):
        self.account_id = account_id
        self.region = region

    def build(self, findings: list[Finding]) -> dict:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_counts[f.severity] += 1

        overall_risk = 0.0
        if findings:
            overall_risk = max(f.risk_score for f in findings)

        return {
            "scan_metadata": {
                "account_id": self.account_id,
                "region": self.region,
                "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tool": "iam-privesc-graph",
            },
            "summary": {
                "total_findings": len(findings),
                "overall_risk_score": round(overall_risk, 1),
                "severity_breakdown": severity_counts,
            },
            "findings": [asdict(f) for f in findings],
        }

    def print_console(self, findings: list[Finding]):
        print(f"\n{'='*70}")
        print(f"  IAM PRIVILEGE ESCALATION REPORT — Account {self.account_id}")
        print(f"{'='*70}\n")

        if not findings:
            print("No escalation paths found.")
            return

        for f in findings:
            print(f"[{f.severity}] {f.finding_id}  (risk={f.risk_score}/100, confidence={f.confidence})")
            print(f"  {f.description}")
            print(f"  Remediation: {f.remediation}")
            print()

    def save_json(self, report: dict, path: str):
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] Report saved to {path}")
