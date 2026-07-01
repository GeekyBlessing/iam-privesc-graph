import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import networkx as nx
from src.engine.models import GraphNode, GraphEdge, NodeType, EdgeType
from src.engine.traversal import PathFinder


def build_test_graph():
    """
    A -> B -> C   (A can modify B's trust, B can modify C's trust)
    D -> D        (D has a self edge, should never appear as a path)
    A is human, B and C are service roles.
    """
    g = nx.DiGraph()
    a = GraphNode(node_id="A", node_type=NodeType.USER, name="A", is_human=True)
    b = GraphNode(node_id="B", node_type=NodeType.ROLE, name="B", is_human=False)
    c = GraphNode(node_id="C", node_type=NodeType.ROLE, name="C", is_human=False)
    d = GraphNode(node_id="D", node_type=NodeType.ROLE, name="D", is_human=False)

    for n in (a, b, c, d):
        g.add_node(n.node_id, node=n)

    g.add_edge("A", "B", edge=GraphEdge("A", "B", EdgeType.CAN_MODIFY_TRUST, confidence=1.0))
    g.add_edge("B", "C", edge=GraphEdge("B", "C", EdgeType.CAN_MODIFY_TRUST, confidence=1.0))
    g.add_edge("D", "D", edge=GraphEdge("D", "D", EdgeType.CAN_PASS_ROLE, confidence=1.0))
    return g


def test_direct_path_found():
    g = build_test_graph()
    finder = PathFinder(g)
    paths = finder._paths_between("A", "B", max_hops=4)
    assert any(p.length == 1 for p in paths)
    print("PASS: direct one hop path A -> B found")


def test_multi_hop_path_found():
    g = build_test_graph()
    finder = PathFinder(g)
    paths = finder._paths_between("A", "C", max_hops=4)
    assert any(p.length == 2 for p in paths)
    chain = [p for p in paths if p.length == 2][0]
    assert chain.edge_types == ["can_modify_trust", "can_modify_trust"]
    print("PASS: multi-hop path A -> B -> C discovered via traversal")


def test_self_edges_do_not_produce_paths():
    g = build_test_graph()
    finder = PathFinder(g)
    paths = finder._paths_between("D", "D", max_hops=4)
    assert len(paths) == 0
    print("PASS: self referential edges do not produce escalation paths")


def test_max_hops_respected():
    g = build_test_graph()
    finder = PathFinder(g)
    paths = finder._paths_between("A", "C", max_hops=1)
    assert len(paths) == 0
    print("PASS: max_hops cutoff correctly excludes paths beyond the limit")


if __name__ == "__main__":
    test_direct_path_found()
    test_multi_hop_path_found()
    test_self_edges_do_not_produce_paths()
    test_max_hops_respected()
    print("\nAll traversal tests passed.")
