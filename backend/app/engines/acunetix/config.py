"""Acunetix engine configuration and environment settings."""

import os
from pydantic import BaseModel, Field


class AcunetixConfig(BaseModel):
    base_url: str = Field(default_factory=lambda: os.getenv("ACUNETIX_BASE_URL", "https://localhost:3443"))
    api_key: str = Field(default_factory=lambda: os.getenv("ACUNETIX_API_KEY", ""))
    verify_ssl: bool = Field(default_factory=lambda: os.getenv("ACUNETIX_VERIFY_SSL", "false").lower() == "true")
    timeout_seconds: int = Field(default=30)
    max_retries: int = Field(default=3)
    rate_limit_per_second: float = Field(default=10.0)
    default_profile_id: Optional[str] = Field(default=None)

    class Config:
        frozen = True
