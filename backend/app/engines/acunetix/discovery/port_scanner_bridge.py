"""Convert open web ports (80, 443, 8080, 8443) to Acunetix target URLs."""

from typing import List, Dict, Any


def port_to_acunetix_targets(ip: str, open_ports: List[int]) -> List[str]:
    targets = []
    for p in open_ports:
        if p in (443, 8443, 9443):
            targets.append(f"https://{ip}:{p}")
        elif p in (80, 8080, 8000, 8888):
            targets.append(f"http://{ip}:{p}")
    return targets
