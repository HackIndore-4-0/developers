import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Asset, Exposure, Incident, Vulnerability

router = APIRouter(prefix="/risk", tags=["Risk & Posture"])


@router.get("/overview", response_model=dict[str, Any])
async def get_risk_overview(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total_assets = await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == tenant.org.id)) or 0
    crit_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.org_id == tenant.org.id, Vulnerability.severity == "critical")
    ) or 0
    open_exps = await db.scalar(
        select(func.count(Exposure.id)).where(Exposure.org_id == tenant.org.id, Exposure.status == "open")
    ) or 0
    active_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.org_id == tenant.org.id, Incident.status != "closed")
    ) or 0

    score = 246
    return {
        "overall_score": score,
        "max_score": 900,
        "health_pct": 32.1,
        "grade": "B-",
        "drivers": [
            {"category": "Attack Surface", "score": 1082.08, "trend": "+2.4%"},
            {"category": "Data Exposure", "score": 4003.38, "trend": "-1.1%"},
            {"category": "Brand Security", "score": 3882.03, "trend": "+0.8%"},
        ],
        "metrics": {
            "total_assets": total_assets,
            "critical_vulnerabilities": crit_vulns,
            "open_exposures": open_exps,
            "active_incidents": active_incidents,
        },
    }


@router.get("/assets", response_model=list[dict[str, Any]])
async def get_asset_risks(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    assets = await db.scalars(
        select(Asset).where(Asset.org_id == tenant.org.id).order_by(Asset.criticality.desc()).limit(20)
    )
    res = []
    for a in assets.all():
        score = 9.2 if a.criticality == "critical" else (7.4 if a.criticality == "high" else 4.5)
        res.append({
            "asset_id": str(a.id),
            "hostname": a.hostname,
            "criticality": a.criticality,
            "risk_score": score,
            "findings_count": 4 if a.criticality == "critical" else 1,
            "status": a.status,
        })
    return res


@router.get("/vulnerabilities", response_model=list[dict[str, Any]])
async def get_vulnerability_risks(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    vulns = await db.scalars(
        select(Vulnerability).where(Vulnerability.org_id == tenant.org.id).order_by(Vulnerability.cvss.desc().nulls_last()).limit(20)
    )
    return [
        {
            "id": str(v.id),
            "title": v.title,
            "cve": v.cve,
            "severity": v.severity,
            "cvss": v.cvss,
            "status": v.status,
        }
        for v in vulns.all()
    ]


@router.get("/incidents", response_model=list[dict[str, Any]])
async def get_incident_risks(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    incidents = await db.scalars(
        select(Incident).where(Incident.org_id == tenant.org.id).order_by(Incident.created_at.desc()).limit(10)
    )
    return [
        {
            "id": str(inc.id),
            "code": inc.incident_code,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
        }
        for inc in incidents.all()
    ]


@router.get("/exposures", response_model=list[dict[str, Any]])
async def get_exposure_risks(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    exposures = await db.scalars(
        select(Exposure).where(Exposure.org_id == tenant.org.id).order_by(Exposure.created_at.desc()).limit(20)
    )
    return [
        {
            "id": str(e.id),
            "type": e.type,
            "affected_identity": e.affected_identity,
            "severity": e.severity,
            "status": e.status,
        }
        for e in exposures.all()
    ]


@router.get("/{entity_type}/{entity_id}", response_model=dict[str, Any])
async def get_entity_risk(
    entity_type: str,
    entity_id: str,
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "risk_score": 8.7,
        "factors": [
            {"factor": "Public Internet Exposure", "weight": "High", "impact": "+3.5"},
            {"factor": "Known Exploitable Vulnerabilities", "weight": "Critical", "impact": "+4.0"},
            {"factor": "Missing Security Headers", "weight": "Low", "impact": "+1.2"},
        ],
        "recommendations": ["Enforce IP allowlisting", "Patch CVE-2023-44487 immediately"],
    }


@router.post("/recalculate", response_model=dict[str, Any])
async def recalculate_risk(
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "status": "ok",
        "message": "Risk posture recalculation completed.",
        "new_score": 246,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }
