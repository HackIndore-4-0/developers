"""Choke point analysis endpoints for Acunetix scans."""

from fastapi import APIRouter
from typing import Dict, Any, List
from app.engines.acunetix.graph.choke_point_bridge import build_acunetix_attack_graph
from app.engines.acunetix.graph.cut_analyzer import find_top_choke_points

router = APIRouter(prefix="/acunetix/chokepoints", tags=["Acunetix Choke Points"])


@router.post("/analyze")
async def analyze_chokepoints(vulnerabilities: List[Dict[str, Any]]):
    G = build_acunetix_attack_graph(vulnerabilities)
    chokepoints = find_top_choke_points(G)
    return {"chokepoints": chokepoints, "total_nodes": len(G)}
