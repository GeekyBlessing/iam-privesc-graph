import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

from engine.graph_builder import IAMGraphBuilder
from engine.traversal import PathFinder
from engine.scoring import RiskScorer
from engine.consolidation import consolidate
from engine.sigma_gen import SigmaRuleGenerator

ACCOUNT_ID = "358487322954"
REGION = "eu-north-1"

if __name__ == "__main__":
    builder = IAMGraphBuilder(region=REGION)
    graph = builder.build()

    finder = PathFinder(graph)
    paths = finder.find_paths_to_high_value_targets(max_hops=4)

    out_degree_by_control = {}
    for src, dst, data in graph.edges(data=True):
        edge = data["edge"]
        if edge.edge_type.value in ("can_modify_trust", "can_attach_policy", "can_add_user_to_group"):
            out_degree_by_control[src] = out_degree_by_control.get(src, 0) + 1
    high_value_ids = {n for n, count in out_degree_by_control.items() if count >= 3}

    scorer = RiskScorer(graph, high_value_node_ids=high_value_ids)
    raw_findings = scorer.build_findings(paths)
    findings = consolidate(raw_findings)

    print(f"\n{'='*70}")
    print(f"  IAM PRIVILEGE ESCALATION REPORT — Account {ACCOUNT_ID}")
    print(f"  ({len(raw_findings)} raw paths consolidated to {len(findings)} root-cause findings)")
    print(f"{'='*70}\n")

    for f in findings:
        print(f"[{f.severity}] {f.finding_id}  (risk={f.risk_score}/100, blast_radius={f.blast_radius_count})")
        print(f"  {f.description}")
        print(f"  Remediation: {f.remediation}")
        print()

    os.makedirs("output", exist_ok=True)
    report = {
        "scan_metadata": {"account_id": ACCOUNT_ID, "region": REGION, "tool": "iam-privesc-graph"},
        "summary": {
            "raw_paths_found": len(raw_findings),
            "consolidated_findings": len(findings),
            "severity_breakdown": {
                s: len([f for f in findings if f.severity == s])
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            },
        },
        "findings": [f.__dict__ for f in findings],
    }
    with open("output/privesc_report.json", "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Report saved to output/privesc_report.json")

    print(f"\n{'='*70}")
    print(f"  GENERATING SIGMA DETECTION RULES")
    print(f"{'='*70}\n")

    sigma_gen = SigmaRuleGenerator(account_id=ACCOUNT_ID)
    rules = sigma_gen.generate_all(findings)
    sigma_gen.save_rules(rules, "output/sigma_rules")
    print(f"\n[+] {len(rules)} Sigma rule(s) generated from {len(findings)} finding(s)")
