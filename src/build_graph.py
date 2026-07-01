import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from engine.graph_builder import IAMGraphBuilder

if __name__ == "__main__":
    builder = IAMGraphBuilder(region="eu-north-1")
    graph = builder.build()

    print("\n--- Nodes ---")
    for node_id, data in graph.nodes(data=True):
        n = data["node"]
        print(f"  [{n.node_type.value}] {n.name} ({'human' if n.is_human else 'service'})")

    print("\n--- Edges ---")
    for src, dst, data in graph.edges(data=True):
        e = data["edge"]
        print(f"  {src} --[{e.edge_type.value}, conf={e.confidence:.2f}]--> {dst}")
