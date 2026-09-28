import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Subdomain, SubdomainHistory
from app.schemas.domain import SubdomainCreate, SubdomainHistoryOut, SubdomainOut

router = APIRouter(prefix="/subdomains", tags=["Subdomains"])


@router.get("", response_model=list[SubdomainOut])
async def list_subdomains(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    stmt = select(Subdomain).where(Subdomain.org_id == tenant.org.id)
    if q:
        stmt = stmt.where(Subdomain.domain.ilike(f"%{q}%"))
    stmt = stmt.order_by(Subdomain.created_at.desc()).limit(limit if isinstance(limit, int) else 50).offset(offset if isinstance(offset, int) else 0)
    result = await db.scalars(stmt)
    return result.all()


@router.post("/discover", response_model=list[SubdomainOut], status_code=status.HTTP_201_CREATED)
async def discover_subdomains(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    domain = body.get("domain", "aurora.ai")
    sample_subdomains = [
        f"api.{domain}",
        f"staging.{domain}",
        f"vpn.{domain}",
        f"mail.{domain}",
        f"auth.{domain}",
    ]
    created = []
    for s in sample_subdomains:
        existing = await db.scalar(
            select(Subdomain).where(Subdomain.org_id == tenant.org.id, Subdomain.domain == s)
        )
        if not existing:
            sub = Subdomain(
                org_id=tenant.org.id,
                domain=s,
                parent_domain=domain,
                ips=["203.0.113.10"],
                technologies=["nginx", "Linux"],
                status="active",
                status_code=200,
                discoveries=1,
            )
            db.add(sub)
            created.append(sub)
    await db.commit()
    for c in created:
        await db.refresh(c)
    return created or await list_subdomains(tenant=tenant, db=db)


@router.get("/{subdomain_id}", response_model=SubdomainOut)
async def get_subdomain(
    subdomain_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    sub = await db.scalar(
        select(Subdomain).where(Subdomain.id == subdomain_id, Subdomain.org_id == tenant.org.id)
    )
    if not sub:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Subdomain not found")
    return sub


@router.get("/{subdomain_id}/history", response_model=list[SubdomainHistoryOut])
async def get_subdomain_history(
    subdomain_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    history = await db.scalars(
        select(SubdomainHistory).where(SubdomainHistory.subdomain_id == subdomain_id)
    )
    return history.all()
