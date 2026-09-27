"""Target discovery and synchronization manager."""

from typing import List, Dict, Any
from app.engines.acunetix.client import AcunetixClient


class AcunetixTargetManager:
    """Manages target lifecycle, group assignments, and discovery sync."""

    def __init__(self, client: AcunetixClient):
        self.client = client

    async def sync_discovered_domains(self, domains: List[str]) -> List[str]:
        """Ensure all discovered domains exist as Acunetix targets."""
        existing = await self.client.get_targets(limit=500)
        existing_addrs = {t.get("address", "").rstrip("/") for t in existing}

        created_ids = []
        for domain in domains:
            cleaned = domain.strip().rstrip("/")
            if cleaned and cleaned not in existing_addrs:
                res = await self.client.add_target(cleaned, description="Auto-discovered asset")
                created_ids.append(res.get("target_id", ""))

        return created_ids
