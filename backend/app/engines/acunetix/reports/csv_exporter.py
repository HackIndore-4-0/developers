"""CSV finding table exporter."""

import io
import csv
from typing import List, Dict, Any


def export_findings_csv(findings: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "name", "severity", "cwe", "url", "confidence"])
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "id": f.get("id", ""),
            "name": f.get("name", ""),
            "severity": f.get("severity", ""),
            "cwe": f.get("cwe", ""),
            "url": f.get("url", ""),
            "confidence": f.get("confidence", 100),
        })
    return output.getvalue()
