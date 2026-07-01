"""
Generates Sigma-format detection rules from IAM privesc findings.
Each rule watches CloudTrail for the specific API calls that enable
the escalation technique, scoped to the principal(s) identified as
capable of the technique — turning an offensive finding into a
blue-team detection (bridges into the Sentinel Rules project).
"""
import yaml
import uuid
import datetime
from dataclasses import dataclass
from .consolidation import ConsolidatedFinding


# Maps our internal edge/technique names to the actual CloudTrail
# eventName(s) that would appear when the technique is exercised,
# plus the MITRE ATT&CK technique ID most representative of the action.
TECHNIQUE_TO_CLOUDTRAIL = {
    "can_modify_trust": {
        "event_names": ["UpdateAssumeRolePolicy"],
        "mitre_technique": "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "mitre_tactic": "privilege-escalation",
    },
    "can_add_user_to_group": {
        "event_names": ["AddUserToGroup"],
        "mitre_technique": "T1098",  # Account Manipulation
        "mitre_tactic": "privilege-escalation",
    },
    "can_attach_policy": {
        "event_names": ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"],
        "mitre_technique": "T1098.001",  # Additional Cloud Credentials
        "mitre_tactic": "privilege-escalation",
    },
    "can_create_policy_version": {
        "event_names": ["CreatePolicyVersion", "SetDefaultPolicyVersion"],
        "mitre_technique": "T1098.003",
        "mitre_tactic": "privilege-escalation",
    },
    "can_pass_role": {
        "event_names": ["PassRole"],
        "mitre_technique": "T1098.003",
        "mitre_tactic": "privilege-escalation",
    },
    "can_assume": {
        "event_names": ["AssumeRole"],
        "mitre_technique": "T1548.005",  # Abuse Elevation Control Mechanism: Temp Elevated Cloud Access
        "mitre_tactic": "privilege-escalation",
    },
}


class SigmaRuleGenerator:
    def __init__(self, account_id: str):
        self.account_id = account_id

    def generate(self, finding: ConsolidatedFinding) -> dict:
        """Generates one Sigma rule per unique technique in a finding's chain."""
        # For chained findings, generate a rule per technique in the sequence
        # (each hop is independently detectable in CloudTrail)
        unique_techniques = list(dict.fromkeys(finding.technique_chain))
        primary = unique_techniques[0]
        mapping = TECHNIQUE_TO_CLOUDTRAIL.get(primary)
        if not mapping:
            return None

        rule_id = str(uuid.uuid4())
        title = f"IAM Privilege Escalation - {finding.source} {primary.replace('_', ' ')}"

        sigma_rule = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": (
                f"Detects {primary.replace('_', ' ')} actions performed by "
                f"{finding.source}, identified via IAM graph analysis as capable "
                f"of reaching {finding.blast_radius_count} target principal(s). "
                f"Finding ref: {finding.finding_id}"
            ),
            "references": [
                f"internal://iam-privesc-graph/{finding.finding_id}"
            ],
            "author": "Toriola Opeyemi - Sentinel Rules",
            "date": datetime.date.today().isoformat(),
            "tags": [
                f"attack.{mapping['mitre_tactic']}",
                f"attack.{mapping['mitre_technique'].lower()}",
            ],
            "logsource": {
                "product": "aws",
                "service": "cloudtrail",
            },
            "detection": {
                "selection": {
                    "eventSource": "iam.amazonaws.com",
                    "eventName": mapping["event_names"] if len(mapping["event_names"]) > 1
                                 else mapping["event_names"][0],
                    "userIdentity.arn|contains": finding.source,
                },
                "condition": "selection",
            },
            "fields": [
                "eventTime", "userIdentity.arn", "eventName",
                "requestParameters", "sourceIPAddress",
            ],
            "falsepositives": [
                "Legitimate administrative role/policy updates by authorized personnel",
                "Automated infrastructure-as-code deployments (Terraform/CloudFormation) "
                "modifying trust policies as part of normal operations",
            ],
            "level": self._sigma_level(finding.severity),
        }
        return sigma_rule

    @staticmethod
    def _sigma_level(severity: str) -> str:
        mapping = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        return mapping.get(severity, "medium")

    def generate_all(self, findings: list[ConsolidatedFinding]) -> list[dict]:
        rules = []
        seen_titles = set()
        for f in findings:
            rule = self.generate(f)
            if rule and rule["title"] not in seen_titles:
                seen_titles.add(rule["title"])
                rules.append(rule)
        return rules

    @staticmethod
    def save_rules(rules: list[dict], output_dir: str):
        import os
        os.makedirs(output_dir, exist_ok=True)
        for rule in rules:
            safe_name = rule["title"].lower().replace(" ", "_").replace("-", "_")
            safe_name = "".join(c for c in safe_name if c.isalnum() or c == "_")
            path = os.path.join(output_dir, f"{safe_name}.yml")
            with open(path, "w") as fh:
                yaml.dump(rule, fh, sort_keys=False, default_flow_style=False)
            print(f"[+] Sigma rule saved: {path}")
