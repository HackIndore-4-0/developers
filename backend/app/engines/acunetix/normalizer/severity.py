"""Severity normalizer and CVSS translation."""

from typing import Dict, Any


def map_acunetix_severity(severity_int: int) -> str:
    """Map Acunetix integer severity to standardized string label."""
    mapping = {
        3: "critical",
        2: "high",
        1: "medium",
        0: "low",
    }
    return mapping.get(severity_int, "info")


def compute_cvss_score(severity: str, cvss_vector: str = "") -> float:
    """Estimate base CVSS score from severity if vector is missing."""
    scores = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
        "info": 0.0,
    }
    return scores.get(severity.lower(), 0.0)
