"""Report download and generation endpoints."""

from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter(prefix="/acunetix/reports", tags=["Acunetix Reports"])


@router.get("/templates")
async def list_report_templates():
    return [
        {"id": "sox", "name": "Sarbanes-Oxley Compliance Report"},
        {"id": "pci", "name": "PCI-DSS v4.0 Report"},
        {"id": "owasp", "name": "OWASP API Security Top 10"},
        {"id": "exec", "name": "Executive Summary"},
    ]
