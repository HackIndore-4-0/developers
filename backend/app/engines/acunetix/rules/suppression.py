"""False positive suppression and allowlist filters."""

from typing import List, Dict, Any


def filter_suppressed(findings: List[Dict[str, Any]], suppression_rules: List[str]) -> List[Dict[str, Any]]:
    rules_lower = {r.lower() for r in suppression_rules}
    return [f for f in findings if f.get("name", "").lower() not in rules_lower]
