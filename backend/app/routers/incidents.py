import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import (
    Incident,
    IncidentAsset,
    IncidentEvent,
    IncidentIOC,
    IncidentTimeline,
)
from app.schemas.domain import (
    IncidentAssetOut,
    IncidentCreate,
    IncidentEventOut,
    IncidentIOCOut,
    IncidentOut,
    IncidentTimelineOut,
    IncidentUpdate,
)

router = APIRouter(tags=["Incidents & Attack Graphs"])


@router.get("/incidents", response_model=list[IncidentOut])
async def list_incidents(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = select(Incident).where(Incident.org_id == tenant.org.id)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    stmt = stmt.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    result = await db.scalars(stmt)
    return result.all()


@router.post("/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = Incident(
        org_id=tenant.org.id,
        incident_code=f"INC-{uuid.uuid4().hex[:4].upper()}",
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        stage=1,
        assignee=body.assignee,
        ttp=body.ttp or "Initial Access",
        attack_chain=[
            {"node": "External IP", "type": "ip", "state": "compromised"},
            {"node": "Auth Service", "type": "service", "state": "abused"},
            {"node": "Database", "type": "db", "state": "targeted"},
        ],
    )
    db.add(inc)
    await db.flush()

    timeline = IncidentTimeline(
        incident_id=inc.id,
        title="Incident created",
        description=f"Incident {inc.incident_code} opened by analyst",
        actor=tenant.user.name or tenant.user.email,
    )
    event = IncidentEvent(
        incident_id=inc.id,
        event_type="incident.created",
        description="Initial security incident created",
        user_name=tenant.user.name or tenant.user.email,
    )
    db.add_all([timeline, event])
    await db.commit()
    await db.refresh(inc)
    return inc


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.org_id == tenant.org.id)
    )
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return inc


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.org_id == tenant.org.id)
    )
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")

    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(inc, k, v)
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/incidents/{id}/assign", response_model=IncidentOut)
async def assign_incident(
    id: uuid.UUID,
    body: dict[str, str],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(select(Incident).where(Incident.id == id, Incident.org_id == tenant.org.id))
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    inc.assignee = body.get("assignee", tenant.user.name or tenant.user.email)
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/incidents/{id}/acknowledge", response_model=IncidentOut)
async def acknowledge_incident(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(select(Incident).where(Incident.id == id, Incident.org_id == tenant.org.id))
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    inc.status = "investigating"
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/incidents/{id}/close", response_model=IncidentOut)
async def close_incident(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(select(Incident).where(Incident.id == id, Incident.org_id == tenant.org.id))
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    inc.status = "closed"
    inc.stage = 5
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/incidents/{id}/reopen", response_model=IncidentOut)
async def reopen_incident(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(select(Incident).where(Incident.id == id, Incident.org_id == tenant.org.id))
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    inc.status = "investigating"
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/incidents/{id}/escalate", response_model=IncidentOut)
async def escalate_incident(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inc = await db.scalar(select(Incident).where(Incident.id == id, Incident.org_id == tenant.org.id))
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    inc.severity = "critical"
    await db.commit()
    await db.refresh(inc)
    return inc


@router.get("/incidents/{id}/timeline", response_model=list[IncidentTimelineOut])
async def get_incident_timeline(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    timelines = await db.scalars(
        select(IncidentTimeline).where(IncidentTimeline.incident_id == id).order_by(IncidentTimeline.occurred_at.asc())
    )
    return timelines.all()


@router.get("/incidents/{id}/events", response_model=list[IncidentEventOut])
async def get_incident_events(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    events = await db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == id).order_by(IncidentEvent.occurred_at.asc())
    )
    return events.all()


@router.get("/incidents/{id}/assets", response_model=list[IncidentAssetOut])
async def get_incident_assets(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    assets = await db.scalars(select(IncidentAsset).where(IncidentAsset.incident_id == id))
    return assets.all()


@router.get("/incidents/{id}/users", response_model=list[dict[str, Any]])
async def get_incident_users(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    return [
        {"name": tenant.user.name or "User", "email": tenant.user.email, "role": "Investigator"},
    ]


@router.get("/incidents/{id}/iocs", response_model=list[IncidentIOCOut])
async def get_incident_iocs(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    iocs = await db.scalars(select(IncidentIOC).where(IncidentIOC.incident_id == id))
    return iocs.all()


@router.get("/incidents/{id}/evidence", response_model=list[dict[str, Any]])
async def get_incident_evidence(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    return [
        {"type": "Network", "description": "Outbound connection to 203.0.113.42:8443", "timestamp": "2025-09-13T19:32:15Z"},
        {"type": "Process", "description": "Suspicious execution of encoded payload", "timestamp": "2025-09-13T19:33:02Z"},
        {"type": "Auth", "description": "Service token used from external IP", "timestamp": "2025-09-13T19:35:00Z"},
    ]


# ---------- Attack Graphs & Attack Timeline ----------


@router.get("/incidents/{id}/attack-timeline", response_model=dict[str, Any])
async def get_attack_timeline(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    return {
        "incident_id": str(id),
        "stages": [
            {"stage": "Initial Access", "technique": "T1190 - Exploit Public-Facing App", "time": "2025-09-13T19:30:00Z"},
            {"stage": "Execution", "technique": "T1059 - Command & Scripting Interpreter", "time": "2025-09-13T19:32:00Z"},
            {"stage": "Persistence", "technique": "T1078 - Valid Accounts", "time": "2025-09-13T19:35:00Z"},
            {"stage": "Exfiltration", "technique": "T1048 - Exfiltration Over Alternative Protocol", "time": "2025-09-13T19:40:00Z"},
        ],
    }


@router.post("/incidents/{id}/attack-timeline/generate", response_model=dict[str, Any])
async def generate_attack_timeline(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    return await get_attack_timeline(id=id, tenant=tenant, db=db)


@router.get("/incidents/{id}/attack-graph", response_model=dict[str, Any])
@router.post("/incidents/{id}/attack-graph", response_model=dict[str, Any])
async def get_incident_attack_graph(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    return {
        "incident_id": str(id),
        "nodes": [
            {"id": "c2-ip", "label": "203.0.113.42", "kind": "threat_ip", "severity": "critical"},
            {"id": "vpn-gateway", "label": "vpn.aurora.ai", "kind": "asset", "severity": "high"},
            {"id": "auth-service", "label": "auth.aurora.ai", "kind": "service", "severity": "high"},
            {"id": "core-db", "label": "db.aurora.ai", "kind": "database", "severity": "critical"},
        ],
        "edges": [
            {"source": "c2-ip", "target": "vpn-gateway", "label": "BRUTE_FORCE"},
            {"source": "vpn-gateway", "target": "auth-service", "label": "LATERAL_MOVE"},
            {"source": "auth-service", "target": "core-db", "label": "DATA_ACCESS"},
        ],
    }


@router.get("/attack-graphs", response_model=list[dict[str, Any]])
async def list_attack_graphs(
    tenant: TenantContext = Depends(get_tenant),
):
    return [
        {
            "id": "ag-01",
            "title": "Default Attack Graph",
            "nodes_count": 8,
            "edges_count": 12,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]


@router.get("/attack-graphs/{graph_id}", response_model=dict[str, Any])
async def get_attack_graph(
    graph_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "id": graph_id,
        "nodes": [
            {"id": "internet", "label": "Internet", "kind": "cloud"},
            {"id": "web-app", "label": "app.aurora.ai", "kind": "asset"},
            {"id": "api-service", "label": "api.aurora.ai", "kind": "service"},
            {"id": "database", "label": "db.aurora.ai", "kind": "database"},
        ],
        "edges": [
            {"source": "internet", "target": "web-app", "label": "HTTP_TRAFFIC"},
            {"source": "web-app", "target": "api-service", "label": "API_CALL"},
            {"source": "api-service", "target": "database", "label": "SQL_QUERY"},
        ],
    }


@router.post("/attack-graphs/generate", response_model=dict[str, Any])
async def generate_attack_graph(
    tenant: TenantContext = Depends(get_tenant),
):
    return await get_attack_graph(graph_id="ag-generated", tenant=tenant)
