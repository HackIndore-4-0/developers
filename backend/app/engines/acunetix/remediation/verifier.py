"""Re-scan scheduler to verify vulnerability fixes."""

from typing import Dict, Any
from app.engines.acunetix.client import AcunetixClient


async def schedule_verification_scan(client: AcunetixClient, target_id: str, vuln_id: str) -> Dict[str, Any]:
    """Trigger a fast targeted verification scan."""
    return await client._request("POST", "/api/v1/scans", json={
        "target_id": target_id,
        "profile_id": None,
    })
