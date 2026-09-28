"""Generate Markdown developer remediation guide."""

from typing import List, Dict, Any


def generate_dev_checklist(findings: List[Dict[str, Any]]) -> str:
    lines = ["# Developer Remediation Checklist\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {f.get('name', 'Vulnerability')} ({f.get('severity', '').upper()})")
        lines.append(f"- **URL**: `{f.get('url', '')}`")
        lines.append(f"- **CWE**: {f.get('cwe', 'CWE-Unknown')}")
        lines.append(f"- **Detail**: {f.get('detail', 'N/A')}\n")
    return "\n".join(lines)
