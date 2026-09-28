"""Acunetix Scan model schemas."""

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AcunetixScanCreate(BaseModel):
    target_id: str
    profile_id: Optional[str] = None
    schedule: Dict[str, Any] = Field(default_factory=lambda: {"disable": False, "start_date": None, "time_sensitive": False})


class AcunetixScanResponse(BaseModel):
    scan_id: str
    target_id: str
    target_address: Optional[str] = None
    status: str
    current_session: Optional[Dict[str, Any]] = None
