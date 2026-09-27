"""Map vulnerabilities to OWASP API Security Top 10."""

from typing import List, Dict, Any

OWASP_CATEGORIES = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}


def categorize_owasp(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    categorized: Dict[str, List[Dict[str, Any]]] = {k: [] for k in OWASP_CATEGORIES}
    for f in findings:
        name = f.get("name", "").lower()
        if "idor" in name or "bola" in name:
            categorized["API1:2023"].append(f)
        elif "auth" in name or "jwt" in name:
            categorized["API2:2023"].append(f)
        elif "ssrf" in name:
            categorized["API7:2023"].append(f)
        else:
            categorized["API8:2023"].append(f)
    return categorized
