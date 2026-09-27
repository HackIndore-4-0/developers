"""Vulnerability query endpoints."""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from app.engines.acunetix.client import AcunetixClient

router = APIRouter(prefix="/acunetix/vulnerabilities", tags=["Acunetix Vulnerabilities"])


@router.get("/{scan_id}/{session_id}")
async def get_vulns(scan_id: str, session_id: str):
    client = AcunetixClient()
    try:
        return await client.get_scan_vulnerabilities(scan_id, session_id)
    finally:
        await client.close()
