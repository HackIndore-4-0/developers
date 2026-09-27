"""Unified high-level Acunetix service facade."""

from typing import List, Dict, Any
from app.engines.acunetix.client import AcunetixClient
from app.engines.acunetix.graph.choke_point_bridge import build_acunetix_attack_graph
from app.engines.acunetix.graph.cut_analyzer import find_top_choke_points


class AcunetixService:
    """Service facade orchestrating client, normalizer, and graph engine."""

    def __init__(self, client: AcunetixClient):
        self.client = client

    async def get_choke_point_summary(self, scan_id: str, session_id: str) -> Dict[str, Any]:
        vulns = await self.client.get_scan_vulnerabilities(scan_id, session_id)
        G = build_acunetix_attack_graph(vulns)
        chokepoints = find_top_choke_points(G)
        return {
            "scan_id": scan_id,
            "vulnerabilities_count": len(vulns),
            "chokepoints": chokepoints,
        }
