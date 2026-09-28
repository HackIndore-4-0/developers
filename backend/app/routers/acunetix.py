"""FastAPI Router for Acunetix integration."""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from app.engines.acunetix.client import AcunetixClient
from app.engines.acunetix.orchestrator.health_check import check_acunetix_health

router = APIRouter(prefix="/acunetix", tags=["Acunetix"])


@router.get("/health")
async def get_health():
    client = AcunetixClient()
    try:
        return await check_acunetix_health(client)
    finally:
        await client.close()
