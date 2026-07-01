import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from engine.graph_builder import IAMGraphBuilder
from engine.traversal import PathFinder

if __name__ == "__main__":
    builder = IAMGraphBuilder(region="eu-north-1")
    graph = builder.build()

    finder = PathFinder(graph)
    paths = finder.find_paths_to_high_value_targets(max_hops=4)

    print(f"\n[+] {len(paths)} escalation path(s) found\n")
    for i, p in enumerate(paths, 1):
        print(f"--- Path {i} (length={p.length}, confidence={p.confidence:.2f}) ---")
        print(p.describe())
        print()
