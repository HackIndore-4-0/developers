"""Synchronize Acunetix vulnerabilities with Jira tickets."""

from typing import Dict, Any


class AcunetixJiraSync:
    def __init__(self, project_key: str):
        self.project_key = project_key

    def create_issue_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[Acunetix] {finding.get('name')}",
                "description": f"URL: {finding.get('url')}\nSeverity: {finding.get('severity')}",
                "issuetype": {"name": "Bug"},
            }
        }
