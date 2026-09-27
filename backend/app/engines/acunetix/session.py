"""Acunetix async HTTP session manager with connection pooling."""

import httpx
from typing import Optional
from app.engines.acunetix.config import AcunetixConfig


class AcunetixSessionManager:
    """Manages persistent httpx.AsyncClient connections to Acunetix."""

    def __init__(self, config: AcunetixConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url.rstrip("/"),
                verify=self.config.verify_ssl,
                timeout=httpx.Timeout(self.config.timeout_seconds),
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
