"""Extract technology stack components from scan headers."""

from typing import List, Dict, Any


def extract_technologies(headers: Dict[str, str]) -> List[str]:
    techs = []
    server = headers.get("server") or headers.get("Server")
    if server:
        techs.append(server)
    powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if powered_by:
        techs.append(powered_by)
    return techs
