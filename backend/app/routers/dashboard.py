from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import Alert, Asset, Exposure, Incident, Vulnerability

router = APIRouter(prefix="/dashboard", tags=["Dashboard Aggregates"])


@router.get("/overview", response_model=dict[str, Any])
async def get_dashboard_overview(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    assets_count = await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == tenant.org.id)) or 0
    vulns_count = await db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.org_id == tenant.org.id)) or 0
    exps_count = await db.scalar(select(func.count(Exposure.id)).where(Exposure.org_id == tenant.org.id)) or 0
    incidents_count = await db.scalar(select(func.count(Incident.id)).where(Incident.org_id == tenant.org.id)) or 0
    alerts_count = await db.scalar(select(func.count(Alert.id)).where(Alert.org_id == tenant.org.id)) or 0

    return {
        "score": {"average": 246, "max": 900, "health_pct": 32.1, "delta": "+2.8%"},
        "breakdown": {
            "attack_surface": 1082.08,
            "data_exposure": 4003.38,
            "brand_security": 3882.03,
        },
        "totals": {
            "assets": assets_count,
            "vulnerabilities": vulns_count,
            "exposures": exps_count,
            "incidents": incidents_count,
            "alerts": alerts_count,
            "open_ports": 34,
        },
        "top_issues": [
            "36 vulnerable SSL certificates were found.",
            "26 vulnerable subdomains found.",
            "12 external IP addresses were discovered with non-standard ports.",
            "6 unpatched infrastructure components identified.",
        ],
    }


@router.get("/assets", response_model=dict[str, Any])
async def get_dashboard_assets(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == tenant.org.id)) or 0
    return {
        "total_assets": total or 120010,
        "total_ips": 203,
        "trend_data": [28, 32, 38, 42, 55, 58, 50, 48, 52, 60, 55, 51],
        "labels": ["03-07", "10-14", "17-21", "24-28"],
        "cloud_providers": [
            "Hangzhou Alibaba Advertising Co.,Ltd.",
            "Alibaba US Technology Co., Ltd.",
            "GOOGLE-CLOUD-PLATFORM",
            "SALESFORCE",
        ],
    }


@router.get("/vulnerabilities", response_model=dict[str, Any])
async def get_dashboard_vulnerabilities(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.org_id == tenant.org.id)) or 0
    return {
        "total_vulnerabilities": total,
        "critical": 3,
        "high": 12,
        "medium": 24,
        "low": 18,
    }


@router.get("/exposures", response_model=dict[str, Any])
async def get_dashboard_exposures(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Exposure.id)).where(Exposure.org_id == tenant.org.id)) or 0
    return {
        "total_exposures": total,
        "credentials": 14,
        "api_keys": 4,
        "stealer_logs": 8,
        "breaches": 12,
    }


@router.get("/incidents", response_model=dict[str, Any])
async def get_dashboard_incidents(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Incident.id)).where(Incident.org_id == tenant.org.id)) or 0
    return {
        "total_incidents": total,
        "critical": 2,
        "high": 3,
        "investigating": 4,
        "contained": 2,
    }


@router.get("/alerts", response_model=dict[str, Any])
async def get_dashboard_alerts(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(Alert.id)).where(Alert.org_id == tenant.org.id)) or 0
    return {
        "total_alerts": total,
        "unassigned": 6,
        "acknowledged": 14,
    }


@router.get("/risk", response_model=dict[str, Any])
async def get_dashboard_risk(
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "score": 246,
        "max": 900,
        "grade": "B-",
        "posture": "Moderate Exposure Risk",
    }


@router.get("/attack-surface-changes", response_model=list[dict[str, Any]])
async def get_attack_surface_changes(
    tenant: TenantContext = Depends(get_tenant),
):
    return [
        {"change": "New port 8020 opened on 170.64.164.154", "type": "port_opened", "time": "2 hours ago"},
        {"change": "Subdomain staging.aurora.ai certificate expired", "type": "cert_expired", "time": "5 hours ago"},
        {"change": "New host discovered: k8s-node-04.aurora.ai", "type": "new_asset", "time": "1 day ago"},
    ]


@router.get("/threat-activity", response_model=list[dict[str, Any]])
async def get_dashboard_threat_activity(
    tenant: TenantContext = Depends(get_tenant),
):
    return [
        {"threat": "APT28 scanning activity observed", "target": "vpn.aurora.ai", "severity": "high", "time": "10m ago"},
        {"threat": "LockBit credential leak detected in dark web forum", "target": "aurora-bank.com", "severity": "critical", "time": "1h ago"},
    ]
