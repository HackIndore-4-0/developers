"""Transform Acunetix findings into standardized Attack Graph nodes."""

from typing import Dict, Any
from app.engines.acunetix.normalizer.cwe_mapper import get_cwe_id
from app.engines.acunetix.normalizer.severity import map_acunetix_severity


def finding_to_attack_node(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an Acunetix raw vulnerability dict into an attack path node."""
    vuln_name = finding.get("vt_name", "Unknown Vulnerability")
    severity = map_acunetix_severity(finding.get("severity", 0))
    cwe_id = get_cwe_id(vuln_name)

    return {
        "id": finding.get("vuln_id", ""),
        "type": "vulnerability",
        "name": vuln_name,
        "severity": severity,
        "cwe": f"CWE-{cwe_id}",
        "url": finding.get("affects_url", ""),
        "detail": finding.get("affects_detail", ""),
        "confidence": finding.get("confidence", 100),
    }
