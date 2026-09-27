"""Acunetix X-Auth authentication header provider."""

from typing import Dict
from app.engines.acunetix.exceptions import AcunetixAuthError


class AcunetixAuthProvider:
    """Manages authentication headers for Acunetix REST API calls."""

    def __init__(self, api_key: str):
        if not api_key:
            self._api_key = ""
        else:
            self._api_key = api_key.strip()

    def get_headers(self) -> Dict[str, str]:
        """Generate authentication headers."""
        if not self._api_key:
            return {"Content-Type": "application/json"}
        return {
            "X-Auth": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def validate(self) -> bool:
        """Validate API key format."""
        return len(self._api_key) >= 16
