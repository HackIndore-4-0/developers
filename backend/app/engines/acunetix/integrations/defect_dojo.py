"""Export Acunetix findings to DefectDojo AppSec platform."""

from typing import List, Dict, Any


def format_defect_dojo_payload(scan_name: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "scan_type": "Acunetix Scan",
        "active": True,
        "verified": True,
        "scan_date": "2026-09-27",
        "findings": findings,
    }
