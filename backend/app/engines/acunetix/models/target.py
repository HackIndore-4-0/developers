"""Acunetix Target schemas."""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class AcunetixTargetCreate(BaseModel):
    address: str
    description: Optional[str] = ""
    criticality: int = Field(default=10, ge=0, le=30)
    type: str = "default"


class AcunetixTargetResponse(BaseModel):
    target_id: str
    address: str
    description: Optional[str] = None
    criticality: int = 10
    type: str = "default"
    last_scan_date: Optional[datetime] = None
