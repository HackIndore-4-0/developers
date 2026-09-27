"""PCI-DSS v4.0 compliance evaluation for web applications."""

from typing import List, Dict, Any


def format_pci_report(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Check against PCI-DSS Requirement 6.4 (AppSec) standards."""
    auto_fail = any(f.get("severity") in ("critical", "high") for f in findings)
    return {
        "standard": "PCI-DSS v4.0 Requirement 6.4",
        "target": target,
        "compliant": not auto_fail,
        "blocking_vulnerabilities": [f for f in findings if f.get("severity") in ("critical", "high")],
    }
