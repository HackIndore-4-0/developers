"""Unit tests for third-party integration formatters."""

from app.engines.acunetix.integrations.jira_sync import AcunetixJiraSync
from app.engines.acunetix.integrations.slack_notifier import format_slack_alert


def test_jira_payload():
    sync = AcunetixJiraSync(project_key="SEC")
    payload = sync.create_issue_payload({"name": "RCE", "url": "https://api.com", "severity": "critical"})
    assert payload["fields"]["project"]["key"] == "SEC"


def test_slack_alert():
    alert = format_slack_alert("Production API Scan", critical_count=2, high_count=3)
    assert alert["color"] == "#e01e5a"
