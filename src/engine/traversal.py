"""
Multi-hop privilege escalation path discovery.
Given the IAM graph, finds chains from low-privilege principals to
high-value targets (e.g. AdministratorAccess-equivalent roles),
scoring each path by weakest-link confidence.
"""
import networkx as nx
from dataclasses import dataclass
from .models import GraphNode, GraphEdge, NodeType


@dataclass
class EscalationPath:
    hops: list[str]           # node_ids in order
    edge_types: list[str]     # edge type per hop
    confidence: float         # weakest-link confidence across the path
    length: int

    def describe(self) -> str:
        parts = []
        for i in range(len(self.hops) - 1):
            parts.append(f"{self.hops[i].split('/')[-1]} --[{self.edge_types[i]}]--> {self.hops[i+1].split('/')[-1]}")
        return "\n".join(parts)


class PathFinder:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def find_paths_to_high_value_targets(self, max_hops: int = 4) -> list[EscalationPath]:
        results = []
        human_sources = [
            n for n, d in self.graph.nodes(data=True)
            if d["node"].is_human
        ]

        for source in human_sources:
            for target in self.graph.nodes():
                if source == target:
                    continue
                results.extend(self._paths_between(source, target, max_hops))

        results.sort(key=lambda p: (p.length, -p.confidence))
        return results

    def _paths_between(self, source: str, target: str, max_hops: int) -> list[EscalationPath]:
        paths = []
        try:
            for raw_path in nx.all_simple_paths(self.graph, source, target, cutoff=max_hops):
                if len(raw_path) < 2:
                    continue
                edge_types = []
                confidences = []
                for i in range(len(raw_path) - 1):
                    edge_data = self.graph.get_edge_data(raw_path[i], raw_path[i + 1])
                    edge: GraphEdge = edge_data["edge"]
                    edge_types.append(edge.edge_type.value)
                    confidences.append(edge.confidence)
                paths.append(EscalationPath(
                    hops=raw_path,
                    edge_types=edge_types,
                    confidence=min(confidences) if confidences else 0.0,
                    length=len(raw_path) - 1,
                ))
        except nx.NodeNotFound:
            pass
        return paths

    def find_admin_reachable(self, admin_node_ids: list[str], max_hops: int = 4) -> list[EscalationPath]:
        """Focused search: paths from any human principal to a known admin node."""
        results = []
        human_sources = [
            n for n, d in self.graph.nodes(data=True)
            if d["node"].is_human
        ]
        for source in human_sources:
            for target in admin_node_ids:
                if source == target:
                    continue
                results.extend(self._paths_between(source, target, max_hops))
        results.sort(key=lambda p: (p.length, -p.confidence))
        return results
