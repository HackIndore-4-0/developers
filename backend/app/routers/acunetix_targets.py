"""Target management endpoints."""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from app.engines.acunetix.client import AcunetixClient

router = APIRouter(prefix="/acunetix/targets", tags=["Acunetix Targets"])


@router.get("/")
async def list_targets():
    client = AcunetixClient()
    try:
        return await client.get_targets()
    finally:
        await client.close()
