import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Alert, AlertEvent, SecurityEvent
from app.schemas.domain import AlertAssignReq, AlertOut, SecurityEventOut

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = select(Alert).where(Alert.org_id == tenant.org.id)
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    result = await db.scalars(stmt)
    return result.all()


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.status = "acknowledged"
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/dismiss", response_model=AlertOut)
async def dismiss_alert(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.status = "dismissed"
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/escalate", response_model=AlertOut)
async def escalate_alert(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.status = "escalated"
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/assign", response_model=AlertOut)
async def assign_alert(
    alert_id: uuid.UUID,
    body: AlertAssignReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.assignee = body.assignee
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/{alert_id}/events", response_model=list[dict[str, Any]])
async def get_alert_events(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert_events = await db.scalars(select(AlertEvent).where(AlertEvent.alert_id == alert_id))
    return [
        {
            "id": str(ae.id),
            "alert_id": str(ae.alert_id),
            "description": ae.description,
            "occurred_at": ae.occurred_at.isoformat(),
        }
        for ae in alert_events.all()
    ]


@router.get("/{alert_id}/related", response_model=list[AlertOut])
async def get_related_alerts(
    alert_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == tenant.org.id)
    )
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Alert not found")
    related = await db.scalars(
        select(Alert)
        .where(Alert.org_id == tenant.org.id, Alert.id != alert_id, Alert.category == alert.category)
        .limit(5)
    )
    return related.all()
