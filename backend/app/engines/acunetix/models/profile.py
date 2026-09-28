"""Acunetix Scanning Profile models."""

from typing import Optional, List
from pydantic import BaseModel


class AcunetixProfile(BaseModel):
    profile_id: str
    name: str
    custom: bool = False
    checks: List[str] = []
