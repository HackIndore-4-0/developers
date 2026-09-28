"""Sanitize and structure HTTP proof-of-concept evidence."""

import re
from typing import Dict, Any


def sanitize_http_traffic(raw_traffic: str) -> str:
    """Redact authorization headers and sensitive credentials from evidence."""
    if not raw_traffic:
        return ""
    sanitized = re.sub(
        r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._\-]+",
        r"[REDACTED]",
        raw_traffic,
    )
    sanitized = re.sub(
        r"(?i)(X-Auth:\s*)[A-Za-z0-9]+",
        r"[REDACTED]",
        sanitized,
    )
    return sanitized
