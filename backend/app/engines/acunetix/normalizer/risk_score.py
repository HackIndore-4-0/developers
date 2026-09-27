"""Quantified risk reduction metric calculator."""

from typing import List, Dict, Any


def calculate_risk_reduction(total_paths: int, neutralized_paths: int) -> float:
    """Calculate percentage risk reduction when a choke point node is patched."""
    if total_paths <= 0:
        return 0.0
    reduction = (neutralized_paths / total_paths) * 100.0
    return round(min(100.0, max(0.0, reduction)), 2)
