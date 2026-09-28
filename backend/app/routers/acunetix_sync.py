"""Manual discovery sync trigger endpoint."""

from fastapi import APIRouter
from typing import List, Dict, Any

router = APIRouter(prefix="/acunetix/sync", tags=["Acunetix Sync"])


@router.post("/trigger")
async def trigger_sync(domains: List[str]):
    return {"status": "queued", "synced_count": len(domains)}
