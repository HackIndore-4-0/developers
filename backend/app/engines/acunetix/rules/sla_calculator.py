"""Calculate vulnerability resolution SLA deadlines."""

from datetime import datetime, timedelta, timezone

SLA_DAYS = {
    "critical": 2,
    "high": 7,
    "medium": 30,
    "low": 90,
}


def compute_sla_deadline(severity: str, discovered_at: datetime) -> datetime:
    days = SLA_DAYS.get(severity.lower(), 90)
    return discovered_at + timedelta(days=days)
