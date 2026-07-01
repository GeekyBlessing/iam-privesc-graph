# IAM Privilege Escalation Graph Engine

A graph based reasoning engine that discovers IAM privilege escalation paths in AWS accounts, including multi hop and cross account chains that pattern matching tools miss. Built to complement AWS Attack Path Analyzer (resource level attack paths) with identity level attack surface analysis, and to feed detections directly into Sentinel Rules.

## Why this is different from a privesc checklist tool

Most open source IAM privesc scanners check an account against a fixed list of known techniques (Rhino Security's iam-privesc-scan being the reference implementation). That approach has two limits:

1. It only finds techniques someone already documented.
2. It cannot see multi hop chains, where no single principal can escalate alone but a sequence of two or three actions across different principals can.

This project instead models the account as a directed graph (principals as nodes, IAM capabilities as edges) and uses graph traversal to *derive* escalation paths, including ones that are not in any public checklist. It also evaluates full AWS policy precedence (explicit deny, SCP ceiling, permission boundary ceiling, identity and resource policy grants, condition key restrictions) rather than treating an attached policy as an automatic grant.

## Architecture
## Core components

**Policy evaluator** (`src/engine/policy_evaluator.py`)
Evaluates whether an action is actually permitted, honoring AWS's real evaluation order: explicit deny anywhere wins, SCPs and permission boundaries act as ceilings rather than grants, and the final allow must come from an identity or resource policy. Condition keys that meaningfully restrict exploitability (MFA required, source IP, org ID, external ID) lower the confidence score on the resulting edge instead of being ignored.

**Graph builder** (`src/engine/graph_builder.py`)
Pulls live IAM state from the target account and constructs a directed graph. AWS service linked roles are filtered out since they are not attacker reachable. Edges are resolved to their actual targets (for example, iam:AttachUserPolicy only creates edges to IAM users, never to roles) rather than collapsed into self referential placeholders.

**Path finder** (`src/engine/traversal.py`)
Uses graph traversal to discover escalation chains up to a configurable hop count, not just direct one hop capabilities. Each path is scored by weakest link confidence across every edge in the chain.

**Risk scorer and consolidation** (`src/engine/scoring.py`, `src/engine/consolidation.py`)
Raw path enumeration produces one entry per (source, target) pair, which balloons quickly (a single principal with account wide trust modify rights can produce 20+ near duplicate paths). The consolidation layer groups by root cause and technique, separating direct one hop findings from multi hop chained findings, so the report reads as prioritized triage instead of a wall of duplicates.

**Sigma rule generator** (`src/engine/sigma_gen.py`)
For every consolidated finding, generates a Sigma format detection rule mapped to the CloudTrail event name(s) that would appear when the technique is exercised, tagged with the relevant MITRE ATT&CK technique ID. This is the bridge from offensive finding to blue team detection.

## Example finding, live account

Run against a real AWS account, the engine surfaced a genuine over permissioning issue: a Lambda execution role intended only to process GuardDuty alerts held account wide `iam:UpdateAssumeRolePolicy` and `iam:AddUserToGroup`, giving it the ability to rewrite the trust policy of every other role in the account and add the primary IAM user to any group. The tool correctly identified this as a two node mutual control cluster (a "God pair") rather than reporting each of the 6+ reachable targets as a separate finding.
## Stack

Python, boto3, NetworkX, PyYAML. No external services required beyond AWS credentials for the target account.

## Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# configure AWS credentials for the target account first
python3 src/generate_report.py
```

Outputs land in `output/`: `privesc_report.json` for the full findings report, and `output/sigma_rules/*.yml` for the generated detections.

## Roadmap

- Cross account trust chain detection, extending the same graph model across an AWS Organization
- Confidence weighted risk scoring that accounts for whether the source principal is human or service controlled
- PDF report output matching the CloudSentinel report format
- Direct integration with Sentinel Rules as a shared detection library

## Related projects

- [AWS Attack Path Analyzer](https://github.com/GeekyBlessing/aws-attack-path-analyzer): resource level attack path discovery, cross account lateral movement
- Sentinel Rules: AWS detection as code engine, Sigma rules mapped to MITRE ATT&CK (in progress)

## Author

Toriola Opeyemi, Cloud Security Engineer
[toriolaopeyemi.com](https://toriolaopeyemi.com) · [github.com/GeekyBlessing](https://github.com/GeekyBlessing)
