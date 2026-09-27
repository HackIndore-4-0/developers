"""Unit tests for attack graph choke point analysis."""

from app.engines.acunetix.graph.choke_point_bridge import build_acunetix_attack_graph
from app.engines.acunetix.graph.cut_analyzer import find_top_choke_points


def test_graph_construction_and_cut(sample_acunetix_vulns):
    G = build_acunetix_attack_graph(sample_acunetix_vulns)
    assert len(G.nodes) > 0
    assert len(G.edges) > 0

    chokepoints = find_top_choke_points(G, top_k=2)
    assert isinstance(chokepoints, list)
