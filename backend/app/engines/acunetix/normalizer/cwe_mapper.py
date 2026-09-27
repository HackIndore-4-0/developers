"""CWE Taxonomy mapper for Acunetix vulnerability template names."""

from typing import Dict, Optional

ACUNETIX_CWE_MAP: Dict[str, int] = {
    "sql injection": 89,
    "blind sql injection": 89,
    "cross-site scripting": 79,
    "stored xss": 79,
    "server-side request forgery": 918,
    "ssrf": 918,
    "broken object level authorization": 639,
    "idor": 639,
    "remote code execution": 94,
    "command injection": 78,
    "path traversal": 22,
    "directory listing": 548,
    "cors misconfiguration": 942,
    "csrf": 352,
    "xml external entity": 611,
}


def get_cwe_id(vuln_name: str) -> int:
    name_lower = vuln_name.lower().strip()
    for pattern, cwe in ACUNETIX_CWE_MAP.items():
        if pattern in name_lower:
            return cwe
    return 1035  # Generic Vulnerable Third Party / Other
