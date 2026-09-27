"""Generate high-level Executive Summary metrics."""

from typing import List, Dict, Any


def generate_executive_summary(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1

    overall_risk = "CRITICAL" if counts["critical"] > 0 else "HIGH" if counts["high"] > 0 else "MEDIUM"
    return {
        "target": target,
        "overall_posture": overall_risk,
        "breakdown": counts,
        "total_issues": len(findings),
    }
