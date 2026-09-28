"""SARIF 2.1.0 exporter for Acunetix findings."""

import json
from typing import List, Dict, Any


def export_sarif(findings: List[Dict[str, Any]]) -> str:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Acunetix", "version": "24.11"}},
            "results": [
                {
                    "ruleId": f.get("cwe", "CWE-000"),
                    "message": {"text": f.get("name", "")},
                    "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                }
                for f in findings
            ]
        }]
    }
    return json.dumps(sarif, indent=2)
