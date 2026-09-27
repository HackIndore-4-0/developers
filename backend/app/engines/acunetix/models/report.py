"""Acunetix Report generation model schemas."""

from typing import Optional, List
from pydantic import BaseModel


class AcunetixReportRequest(BaseModel):
    template_id: str
    source: dict


class AcunetixReportResponse(BaseModel):
    report_id: str
    template_name: str
    status: str
    download_url: Optional[str] = None
