"""
Consolidates findings from per-target enumeration to per-root-cause.

Two distinct finding types, kept separate to avoid mislabeling:
  1. DIRECT capability findings — source has technique X directly reaching
     target Y (1-hop). Blast radius = all Y's reachable via that exact
     technique from that exact source.
  2. CHAINED findings — multi-hop paths where the technique sequence matters
     and must be shown in order, never collapsed into a single technique label.
"""
from dataclasses import dataclass
from .scoring import Finding


@dataclass
class ConsolidatedFinding:
    finding_id: str
    kind: str                          # "direct" | "chained"
    source: str
    technique_chain: list[str]
    blast_radius: list[str]
    blast_radius_count: int
    max_hop_count: int
    confidence: float
    risk_score: float
    severity: str
    description: str
    remediation: str


def consolidate(findings: list[Finding]) -> list[ConsolidatedFinding]:
    direct = [f for f in findings if f.hop_count == 1]
    chained = [f for f in findings if f.hop_count > 1]

    consolidated = []

    # --- Direct findings: safe to group by (source, single technique) ---
    groups: dict[tuple, list[Finding]] = {}
    for f in direct:
        key = (f.source, f.technique_chain[0])
        groups.setdefault(key, []).append(f)

    for (source, technique), members in groups.items():
        members.sort(key=lambda m: -m.risk_score)
        top = members[0]
        targets = sorted({m.target for m in members})
        consolidated.append(ConsolidatedFinding(
            finding_id=f"PRIVESC-{len(consolidated)+1:03d}",
            kind="direct",
            source=source,
            technique_chain=[technique],
            blast_radius=targets,
            blast_radius_count=len(targets),
            max_hop_count=1,
            confidence=top.confidence,
            risk_score=top.risk_score,
            severity=top.severity,
            description=(
                f"{source} holds direct '{technique}' capability reaching "
                f"{len(targets)} target(s): {', '.join(targets)}"
            ),
            remediation=top.remediation,
        ))

    # --- Chained findings: group by (source, FULL technique sequence) —
    # never collapse across different sequences, since order/technique matters ---
    chain_groups: dict[tuple, list[Finding]] = {}
    for f in chained:
        key = (f.source, tuple(f.technique_chain))
        chain_groups.setdefault(key, []).append(f)

    for (source, chain), members in chain_groups.items():
        members.sort(key=lambda m: -m.risk_score)
        top = members[0]
        targets = sorted({m.target for m in members})
        consolidated.append(ConsolidatedFinding(
            finding_id=f"PRIVESC-{len(consolidated)+1:03d}",
            kind="chained",
            source=source,
            technique_chain=list(chain),
            blast_radius=targets,
            blast_radius_count=len(targets),
            max_hop_count=len(chain),
            confidence=top.confidence,
            risk_score=top.risk_score,
            severity=top.severity,
            description=(
                f"{source} can reach {len(targets)} target(s) via chained "
                f"technique sequence [{' -> '.join(chain)}]: {', '.join(targets)}"
            ),
            remediation=top.remediation,
        ))

    consolidated.sort(key=lambda c: (-c.risk_score, c.kind))
    return consolidated
