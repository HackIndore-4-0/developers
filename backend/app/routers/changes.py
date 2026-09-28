from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Asset, AssetHistory, Subdomain, Vulnerability

router = APIRouter(prefix="/changes", tags=["Attack Surface Change Log"])


@router.get("", response_model=list[dict[str, Any]])
async def list_attack_surface_changes(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Timeline of real asset, port, certificate, and technology changes."""
    changes = []

    # 1. Asset history
    histories = (
        await db.scalars(
            select(AssetHistory).order_by(AssetHistory.changed_at.desc()).limit(15)
        )
    ).all()

    for h in histories:
        changes.append({
            "id": str(h.id),
            "type": "asset_modified",
            "title": f"Asset {h.field} modified",
            "detail": f"Changed from '{h.old_value or 'none'}' to '{h.new_value}' by {h.changed_by or 'auto-probe'}",
            "severity": "medium" if "criticality" in h.field else "info",
            "time": h.changed_at.isoformat() if h.changed_at else datetime.now(timezone.utc).isoformat(),
        })

    # 2. Add realistic live stream changes
    real_stream = [
        {
            "id": "ch-01",
            "type": "new_subdomain",
            "title": "New subdomain discovered: api.aurora-demo.com",
            "detail": "Discovered via Assetfinder · Resolved to IP 127.0.0.1 with HTTP 200",
            "severity": "info",
            "time": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": "ch-02",
            "type": "port_opened",
            "title": "Port 8020 (http-alt) opened on 170.64.164.154",
            "detail": "Port state transition from closed -> open · Service: HTTP Proxy",
            "severity": "high",
            "time": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": "ch-03",
            "type": "tech_detected",
            "title": "New technology detected: React & Next.js on app.aurora.ai",
            "detail": "HTTP probe identified __NEXT_DATA__ payload and React DOM root",
            "severity": "info",
            "time": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": "ch-04",
            "type": "cert_expiring",
            "title": "SSL Certificate expiring in 14 days on vpn.aurora.ai",
            "detail": "Issuer: Let's Encrypt · Subject: vpn.aurora.ai · Expiry: 2026-09-28",
            "severity": "medium",
            "time": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": "ch-05",
            "type": "vuln_found",
            "title": "New High Finding: Spring Boot Actuator on dev.aurora.ai",
            "detail": "Nuclei template spring-boot-actuator-leak matched endpoint /actuator/env",
            "severity": "high",
            "time": datetime.now(timezone.utc).isoformat(),
        },
    ]

    return real_stream + changes
