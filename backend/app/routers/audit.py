import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import AuditLog
from app.schemas.domain import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=list[AuditLogOut])
async def list_audit_logs(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    actor: str | None = None,
    action: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    stmt = select(AuditLog).where(AuditLog.org_id == tenant.org.id)
    if actor:
        stmt = stmt.where(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    lim = limit if isinstance(limit, int) else 50
    off = offset if isinstance(offset, int) else 0
    stmt = stmt.order_by(AuditLog.occurred_at.desc()).limit(lim).offset(off)
    result = await db.scalars(stmt)
    return result.all()


@router.get("/export")
async def export_audit_logs(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    logs = await list_audit_logs(tenant=tenant, db=db, limit=200)
    lines = ["id,actor,action,target,occurred_at,ip_address"]
    for l in logs:
        lines.append(f"{l.id},{l.actor},{l.action},{l.target},{l.occurred_at.isoformat()},{l.ip_address or ''}")
    return Response(content="\n".join(lines), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit-logs.csv"})


@router.get("/{id}", response_model=AuditLogOut)
async def get_audit_log(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    log = await db.scalar(
        select(AuditLog).where(AuditLog.id == id, AuditLog.org_id == tenant.org.id)
    )
    if not log:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit log entry not found")
    return log
