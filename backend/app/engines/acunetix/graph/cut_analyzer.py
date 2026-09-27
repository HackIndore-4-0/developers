"""Calculate graph cut and choke points to neutralize maximum attack chains."""

import networkx as nx
from typing import Dict, Any, List, Tuple


def find_top_choke_points(G: nx.DiGraph, top_k: int = 3) -> List[Dict[str, Any]]:
    """Identify nodes whose removal disconnects the highest number of paths."""
    if len(G) <= 1:
        return []

    betweenness = nx.betweenness_centrality(G)
    sorted_nodes = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)

    results = []
    for node, score in sorted_nodes[:top_k]:
        node_data = G.nodes[node]
        results.append({
            "node": node,
            "centrality": round(score, 4),
            "type": node_data.get("type", "unknown"),
            "name": node_data.get("name", node),
        })

    return results
