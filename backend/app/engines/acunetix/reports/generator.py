"""Report generator facade."""

from typing import Dict, Any, List
from app.engines.acunetix.reports.json_exporter import export_findings_json


class AcunetixReportGenerator:
    """Generates standardized security reports from Acunetix scan results."""

    def __init__(self, findings: List[Dict[str, Any]]):
        self.findings = findings

    def generate_json(self) -> str:
        return export_findings_json(self.findings)
