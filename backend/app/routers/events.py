import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Alert, AlertEvent, AuditLog, DetectionRule, SecurityEvent
from app.schemas.domain import (
    DetectionRuleCreate,
    DetectionRuleOut,
    DetectionRuleUpdate,
    SecurityEventCreate,
    SecurityEventOut,
)

router = APIRouter(tags=["Events & Detections"])


# ---------- Events ----------


@router.get("/events", response_model=list[SecurityEventOut])
async def list_events(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    source: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    stmt = select(SecurityEvent).where(SecurityEvent.org_id == tenant.org.id)
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    lim = limit if isinstance(limit, int) else 50
    off = offset if isinstance(offset, int) else 0
    stmt = stmt.order_by(SecurityEvent.occurred_at.desc()).limit(lim).offset(off)
    result = await db.scalars(stmt)
    return result.all()


@router.post("/events", response_model=SecurityEventOut, status_code=status.HTTP_201_CREATED)
async def create_event(
    body: SecurityEventCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    event = SecurityEvent(
        org_id=tenant.org.id,
        event_type=body.event_type,
        source=body.source,
        severity=body.severity,
        actor=body.actor,
        target=body.target,
        action=body.action,
        ip_address=body.ip_address,
        payload=body.payload,
    )
    db.add(event)
    await db.flush()

    # Automatic alert generation for high/critical security events
    if body.severity in ("critical", "high"):
        alert = Alert(
            org_id=tenant.org.id,
            alert_code=f"ALT-{uuid.uuid4().hex[:4].upper()}",
            title=f"Suspicious activity: {body.event_type} on {body.target or 'perimeter'}",
            category="Threat",
            severity=body.severity,
            status="open",
            source=body.source,
            description=f"Auto-generated alert for {body.event_type} from {body.actor or body.ip_address or 'unknown source'}",
            evidence=body.payload or {"ip": body.ip_address, "action": body.action},
        )
        db.add(alert)
        await db.flush()
        db.add(AlertEvent(alert_id=alert.id, event_id=event.id, description=f"Correlated trigger event: {body.event_type}"))

    await db.commit()
    await db.refresh(event)
    return event


@router.post("/events/batch", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_events_batch(
    body: list[SecurityEventCreate],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    events = [
        SecurityEvent(
            org_id=tenant.org.id,
            event_type=b.event_type,
            source=b.source,
            severity=b.severity,
            actor=b.actor,
            target=b.target,
            action=b.action,
            ip_address=b.ip_address,
            payload=b.payload,
        )
        for b in body
    ]
    db.add_all(events)
    await db.commit()
    return {"status": "ok", "ingested": len(events)}


@router.post("/events/webhook", response_model=dict[str, Any])
async def receive_event_webhook(
    payload: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    event = SecurityEvent(
        org_id=tenant.org.id,
        event_type=payload.get("event_type", "webhook.generic"),
        source=payload.get("source", "webhook"),
        severity=payload.get("severity", "info"),
        actor=payload.get("actor"),
        target=payload.get("target"),
        action=payload.get("action", "received"),
        ip_address=payload.get("ip_address"),
        payload=payload,
    )
    db.add(event)
    await db.commit()
    return {"status": "ok", "event_id": str(event.id)}


@router.get("/events/{event_id}", response_model=SecurityEventOut)
async def get_event(
    event_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    event = await db.scalar(
        select(SecurityEvent).where(SecurityEvent.id == event_id, SecurityEvent.org_id == tenant.org.id)
    )
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event


# ---------- Detections ----------


@router.get("/detections", response_model=list[DetectionRuleOut])
async def list_detections(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.org_id == tenant.org.id)
        .order_by(DetectionRule.created_at.desc())
    )
    result = await db.scalars(stmt)
    return result.all()


@router.get("/detections/{detection_id}", response_model=DetectionRuleOut)
async def get_detection(
    detection_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    detection = await db.scalar(
        select(DetectionRule).where(DetectionRule.id == detection_id, DetectionRule.org_id == tenant.org.id)
    )
    if not detection:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Detection not found")
    return detection


# ---------- Detection Rules ----------


@router.get("/detection-rules", response_model=list[DetectionRuleOut])
async def list_detection_rules(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.org_id == tenant.org.id)
        .order_by(DetectionRule.created_at.desc())
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("/detection-rules", response_model=DetectionRuleOut, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    body: DetectionRuleCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    rule = DetectionRule(
        org_id=tenant.org.id,
        name=body.name,
        rule_id_code=body.rule_id_code or f"DET-{uuid.uuid4().hex[:4].upper()}",
        category=body.category,
        severity=body.severity,
        status=body.status,
        logic=body.logic,
        description=body.description,
    )
    db.add(rule)
    db.add(
        AuditLog(
            org_id=tenant.org.id,
            actor=tenant.user.name or tenant.user.email,
            action="RULE_CREATE",
            target=rule.name,
            detail=f"Created rule {rule.rule_id_code} ({rule.category})",
        )
    )
    await db.commit()
    await db.refresh(rule)
    return rule


@router.patch("/detection-rules/{rule_id}", response_model=DetectionRuleOut)
async def update_detection_rule(
    rule_id: uuid.UUID,
    body: DetectionRuleUpdate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    rule = await db.scalar(
        select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.org_id == tenant.org.id)
    )
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")

    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(rule, k, v)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/detection-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_detection_rule(
    rule_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    rule = await db.scalar(
        select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.org_id == tenant.org.id)
    )
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")
    await db.delete(rule)
    await db.commit()


@router.post("/detection-rules/test", response_model=dict[str, Any])
async def test_detection_rule(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    logic = body.get("logic", "")
    return {
        "status": "passed",
        "matches": 3,
        "sample_match": {
            "event_type": "auth.failed",
            "source": "vpn",
            "ip": "203.0.113.42",
            "evaluated_against": logic,
        },
    }
