"""Send high-severity scan notifications to Slack."""

from typing import Dict, Any


def format_slack_alert(scan_name: str, critical_count: int, high_count: int) -> Dict[str, Any]:
    return {
        "text": f"🚨 *Acunetix Security Alert*: Scan `{scan_name}` completed with {critical_count} critical and {high_count} high vulnerabilities.",
        "color": "#e01e5a" if critical_count > 0 else "#ecb22e",
    }
