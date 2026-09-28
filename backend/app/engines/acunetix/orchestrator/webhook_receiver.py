"""Acunetix webhook receiver for asynchronous scan notifications."""

from typing import Dict, Any


def parse_acunetix_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and normalize Acunetix outbound notification event."""
    return {
        "event_type": payload.get("event_type", "scan_finished"),
        "scan_id": payload.get("scan_id"),
        "target_id": payload.get("target_id"),
        "vulns_found": payload.get("vulns_found", 0),
        "status": payload.get("status", "completed"),
    }
