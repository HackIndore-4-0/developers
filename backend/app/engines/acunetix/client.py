"""Full asynchronous REST client for Acunetix Web Vulnerability Scanner."""

from typing import Any, Dict, List, Optional
import httpx
from app.engines.acunetix.config import AcunetixConfig
from app.engines.acunetix.auth import AcunetixAuthProvider
from app.engines.acunetix.session import AcunetixSessionManager
from app.engines.acunetix.rate_limiter import AcunetixRateLimiter
from app.engines.acunetix.exceptions import (
    AcunetixError,
    AcunetixAuthError,
    AcunetixConnectionError,
    AcunetixTargetNotFoundError,
)


class AcunetixClient:
    """Client for Acunetix API v1 endpoints."""

    def __init__(self, config: Optional[AcunetixConfig] = None):
        self.config = config or AcunetixConfig()
        self.auth = AcunetixAuthProvider(self.config.api_key)
        self.session = AcunetixSessionManager(self.config)
        self.limiter = AcunetixRateLimiter(self.config.rate_limit_per_second)

    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        await self.limiter.acquire()
        client = await self.session.get_client()
        headers = self.auth.get_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        try:
            resp = await client.request(method, path, headers=headers, **kwargs)
            if resp.status_code == 401:
                raise AcunetixAuthError("Invalid Acunetix API key or unauthorized access.")
            if resp.status_code == 404:
                raise AcunetixTargetNotFoundError(f"Resource not found at {path}")
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except httpx.RequestError as exc:
            raise AcunetixConnectionError(f"Failed to connect to Acunetix at {path}: {exc}")

    async def get_me(self) -> Dict[str, Any]:
        """Fetch current authenticated user profile."""
        return await self._request("GET", "/api/v1/me")

    async def get_targets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List configured scan targets."""
        data = await self._request("GET", f"/api/v1/targets?l={limit}")
        return data.get("targets", [])

    async def add_target(self, address: str, description: str = "") -> Dict[str, Any]:
        """Add a new target address to Acunetix."""
        payload = {"address": address, "description": description, "criticality": 10}
        return await self._request("POST", "/api/v1/targets", json=payload)

    async def get_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List all scan sessions."""
        data = await self._request("GET", f"/api/v1/scans?l={limit}")
        return data.get("scans", [])

    async def get_scan_vulnerabilities(self, scan_id: str, session_id: str) -> List[Dict[str, Any]]:
        """List vulnerabilities found in a specific scan session."""
        data = await self._request("GET", f"/api/v1/scans/{scan_id}/results/{session_id}/vulnerabilities")
        return data.get("vulnerabilities", [])

    async def close(self):
        await self.session.close()
