"""Remediation matrix scoring based on exploitability and impact."""

from typing import List, Dict, Any


def rank_remediation_priority(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort findings in order of remediation priority score."""
    def _score(f):
        sev_weight = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(f.get("severity", "low"), 10)
        return sev_weight * (f.get("confidence", 100) / 100.0)

    return sorted(findings, key=_score, reverse=True)
