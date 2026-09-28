"""Simulate attack path neutralization when patching specific vulnerabilities."""

import networkx as nx
from typing import Dict, Any


def simulate_patch(G: nx.DiGraph, patch_node: str, source: str, target: str) -> Dict[str, Any]:
    """Simulate removing a node and measure remaining viable paths."""
    initial_paths = len(list(nx.all_simple_paths(G, source, target))) if G.has_node(source) and G.has_node(target) else 0

    G_copy = G.copy()
    if G_copy.has_node(patch_node):
        G_copy.remove_node(patch_node)

    remaining_paths = len(list(nx.all_simple_paths(G_copy, source, target))) if G_copy.has_node(source) and G_copy.has_node(target) else 0
    neutralized = initial_paths - remaining_paths

    return {
        "patch_node": patch_node,
        "initial_paths": initial_paths,
        "remaining_paths": remaining_paths,
        "neutralized_paths": neutralized,
        "efficiency_score": round((neutralized / max(1, initial_paths)) * 100.0, 2),
    }
