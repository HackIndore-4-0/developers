"""Asynchronous scan progress monitor and poller."""

import asyncio
from typing import Callable, Awaitable, Optional, Dict, Any
from app.engines.acunetix.client import AcunetixClient


class AcunetixScanPoller:
    """Polls Acunetix scan status until completion or failure."""

    def __init__(self, client: AcunetixClient, interval_seconds: float = 5.0, timeout_seconds: float = 3600.0):
        self.client = client
        self.interval = interval_seconds
        self.timeout = timeout_seconds

    async def wait_for_completion(
        self,
        scan_id: str,
        on_progress: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:
        elapsed = 0.0
        while elapsed < self.timeout:
            scan = await self.client._request("GET", f"/api/v1/scans/{scan_id}")
            status = scan.get("current_session", {}).get("status")

            if on_progress:
                await on_progress(scan)

            if status in ("completed", "failed", "aborted"):
                return scan

            await asyncio.sleep(self.interval)
            elapsed += self.interval

        raise TimeoutError(f"Scan {scan_id} exceeded maximum polling timeout.")
