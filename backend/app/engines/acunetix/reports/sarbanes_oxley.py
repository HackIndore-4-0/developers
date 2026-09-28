"""Sarbanes-Oxley (SOX) compliance report generator."""

from typing import List, Dict, Any


def format_sox_report(target_url: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format finding data for SOX Section 404 IT control audit compliance."""
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")

    compliance_status = "PASS" if critical_count == 0 and high_count == 0 else "FAIL"
    return {
        "compliance_standard": "Sarbanes-Oxley Act Section 404",
        "target": target_url,
        "status": compliance_status,
        "critical_deficiencies": critical_count,
        "significant_deficiencies": high_count,
        "findings_count": len(findings),
    }
