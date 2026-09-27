"""Builds NetworkX directed attack graph from Acunetix scan results."""

import networkx as nx
from typing import List, Dict, Any
from app.engines.acunetix.normalizer.attack_node import finding_to_attack_node


def build_acunetix_attack_graph(vulnerabilities: List[Dict[str, Any]], entrypoint: str = "INTERNET") -> nx.DiGraph:
    """Convert scan vulnerabilities into a directed multigraph representing attack chains."""
    G = nx.DiGraph()
    G.add_node(entrypoint, type="entrypoint", label="Public Internet")

    for vuln in vulnerabilities:
        node = finding_to_attack_node(vuln)
        node_id = node["id"] or f"vuln_{len(G)}"
        G.add_node(node_id, **node)

        # Connect entrypoint -> vulnerability endpoint
        url_node = f"endpoint:{node.get('url', '')}"
        G.add_node(url_node, type="endpoint", url=node.get("url", ""))
        G.add_edge(entrypoint, url_node, label="HTTP_ACCESS")
        G.add_edge(url_node, node_id, label="EXPLOITS")

    return G
