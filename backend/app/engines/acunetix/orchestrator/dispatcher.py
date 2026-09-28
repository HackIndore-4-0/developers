"""Scan job dispatcher."""

import asyncio
from typing import Dict, Any, Optional
from app.engines.acunetix.client import AcunetixClient


class AcunetixDispatcher:
    """Dispatches new automated scan jobs to Acunetix daemon."""

    def __init__(self, client: AcunetixClient):
        self.client = client

    async def trigger_scan(self, target_id: str, profile_id: Optional[str] = None) -> Dict[str, Any]:
        """Trigger scan on a target."""
        payload = {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        }
        return await self.client._request("POST", "/api/v1/scans", json=payload)
