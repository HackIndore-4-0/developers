import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import EscalationPolicy, NotificationRecord
from app.schemas.domain import (
    EscalationPolicyCreate,
    EscalationPolicyOut,
    EscalationPolicyUpdate,
    NotificationOut,
    NotificationTestReq,
)

router = APIRouter(tags=["Escalation Policies & Notifications"])


# ---------- Escalation Policies ----------


@router.get("/escalation-policies", response_model=list[EscalationPolicyOut])
async def list_escalation_policies(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(EscalationPolicy)
        .where(EscalationPolicy.org_id == tenant.org.id)
        .order_by(EscalationPolicy.created_at.desc())
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("/escalation-policies", response_model=EscalationPolicyOut, status_code=status.HTTP_201_CREATED)
async def create_escalation_policy(
    body: EscalationPolicyCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    policy = EscalationPolicy(
        org_id=tenant.org.id,
        name=body.name,
        severity=body.severity,
        enabled=body.enabled,
        steps=body.steps
        or [
            {"delay": "0m", "target": "SOC Team", "channel": "Slack + Email"},
            {"delay": "15m", "target": "SOC Lead", "channel": "Phone + Slack"},
        ],
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/escalation-policies/{id}", response_model=EscalationPolicyOut)
async def get_escalation_policy(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(EscalationPolicy).where(EscalationPolicy.id == id, EscalationPolicy.org_id == tenant.org.id)
    )
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy


@router.patch("/escalation-policies/{id}", response_model=EscalationPolicyOut)
async def update_escalation_policy(
    id: uuid.UUID,
    body: EscalationPolicyUpdate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(EscalationPolicy).where(EscalationPolicy.id == id, EscalationPolicy.org_id == tenant.org.id)
    )
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found")

    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(policy, k, v)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/escalation-policies/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_escalation_policy(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(EscalationPolicy).where(EscalationPolicy.id == id, EscalationPolicy.org_id == tenant.org.id)
    )
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found")
    await db.delete(policy)
    await db.commit()


# ---------- Notifications ----------


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=100),
):
    stmt = (
        select(NotificationRecord)
        .where(NotificationRecord.org_id == tenant.org.id)
        .order_by(NotificationRecord.sent_at.desc())
        .limit(limit)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.get("/notifications/{id}", response_model=NotificationOut)
async def get_notification(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    notif = await db.scalar(
        select(NotificationRecord).where(NotificationRecord.id == id, NotificationRecord.org_id == tenant.org.id)
    )
    if not notif:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Notification not found")
    return notif


@router.post("/notifications/test", response_model=dict[str, Any])
async def test_notification(
    body: NotificationTestReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    notif = NotificationRecord(
        org_id=tenant.org.id,
        channel=body.channel,
        title=f"Test Notification ({body.channel})",
        message=body.message,
        recipient=body.recipient or tenant.user.email,
        status="sent",
    )
    db.add(notif)
    await db.commit()
    return {"status": "ok", "message": f"Test alert dispatched to {body.channel}"}
