"""Feed discovered subdomains directly into Acunetix target registry."""

from typing import List, Dict, Any


def filter_new_targets(discovered: List[str], existing: List[str]) -> List[str]:
    existing_set = {e.lower().rstrip("/") for e in existing}
    return [d for d in discovered if d.lower().rstrip("/") not in existing_set]
