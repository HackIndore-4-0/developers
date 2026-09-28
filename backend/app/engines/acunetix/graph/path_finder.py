"""Find all simple attack paths from entrypoint to high-value assets."""

import networkx as nx
from typing import List, Dict, Any


def enumerate_attack_paths(G: nx.DiGraph, source: str, target: str) -> List[List[str]]:
    """Find all simple directed paths between source entrypoint and target."""
    if not G.has_node(source) or not G.has_node(target):
        return []
    try:
        return list(nx.all_simple_paths(G, source, target, cutoff=6))
    except Exception:
        return []
