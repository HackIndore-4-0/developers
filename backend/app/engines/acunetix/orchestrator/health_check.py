"""Acunetix health check monitor."""

import time
from typing import Dict, Any
from app.engines.acunetix.client import AcunetixClient


async def check_acunetix_health(client: AcunetixClient) -> Dict[str, Any]:
    """Verify Acunetix connectivity and measure round-trip latency."""
    t0 = time.monotonic()
    try:
        data = await client.get_me()
        latency_ms = (time.monotonic() - t0) * 1000.0
        return {
            "status": "healthy",
            "latency_ms": round(latency_ms, 2),
            "user_email": data.get("email", ""),
        }
    except Exception as exc:
        return {
            "status": "unhealthy",
            "error": str(exc),
        }
