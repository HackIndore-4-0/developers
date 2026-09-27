"""Scan lifecycle control endpoints."""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.engines.acunetix.client import AcunetixClient

router = APIRouter(prefix="/acunetix/scans", tags=["Acunetix Scans"])


@router.get("/")
async def list_scans():
    client = AcunetixClient()
    try:
        return await client.get_scans()
    finally:
        await client.close()
