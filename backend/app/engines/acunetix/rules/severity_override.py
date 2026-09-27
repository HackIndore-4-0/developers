"""Dynamic severity overrides based on environment and network context."""

from typing import Dict, Any


def apply_severity_override(finding: Dict[str, Any], is_public: bool) -> Dict[str, Any]:
    """Elevate severity if finding resides on an externally exposed perimeter."""
    f = finding.copy()
    if is_public and f.get("severity") == "medium":
        f["severity"] = "high"
        f["override_reason"] = "Elevated due to public perimeter exposure"
    return f
