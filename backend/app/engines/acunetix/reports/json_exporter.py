"""JSON findings exporter."""

import json
from typing import List, Dict, Any


def export_findings_json(findings: List[Dict[str, Any]]) -> str:
    return json.dumps({"findings": findings, "count": len(findings)}, indent=2)
