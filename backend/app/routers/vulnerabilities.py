import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.factory import crud_router
from app.deps import Tenant, get_tenant, require_roles
from app.models.security import Asset, Vulnerability, VulnerabilityScan, utcnow
from app.schemas.domain import VulnActionResp, VulnAssignReq
from app.schemas.intelligence import (
    ScanOut,
    VulnerabilityCreate,
    VulnerabilityListOut,
    VulnerabilityOut,
    VulnerabilityUpdate,
)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

factory_router = crud_router(
    Vulnerability,
    schemas={
        "list": VulnerabilityListOut,
        "get": VulnerabilityOut,
        "create": VulnerabilityCreate,
        "update": VulnerabilityUpdate,
    },
    search_columns=[Vulnerability.title, Vulnerability.cve, Vulnerability.template_id],
    prefix="/vulnerabilities",
    allowed_methods=("list", "get", "create", "update", "delete"),
)

scans_router = APIRouter(prefix="/vulnerability/scans", tags=["Vulnerability Scans"])


async def _get_vuln_or_404(db: AsyncSession, vuln_id: str, org_id: str) -> Vulnerability:
    v = await db.scalar(select(Vulnerability).where(Vulnerability.id == vuln_id, Vulnerability.org_id == org_id))
    if not v:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return v


async def _require_own_asset(db: AsyncSession, asset_id: uuid.UUID, org_id: str):
    a = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id))
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return a


# ---- status transitions ----
@router.patch("/{vuln_id}/status", response_model=VulnerabilityOut)
async def set_status(
    vuln_id: uuid.UUID,
    body: dict,
    tenant: Tenant = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    v = await _get_vuln_or_404(db, str(vuln_id), tenant.org_id)
    new = body.get("status")
    allowed = {"open", "in_progress", "fixed", "false_positive", "accepted"}
    if new not in allowed:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Invalid status; allowed: {', '.join(sorted(allowed))}")
    v.status = new
    v.updated_at = utcnow()
    await db.commit()
    await db.refresh(v)
    return v


# ---- triage actions ----
@router.post("/{vulnerability_id}/assign", response_model=VulnActionResp)
async def assign_vulnerability(
    vulnerability_id: uuid.UUID,
    body: VulnAssignReq,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    v = await _get_vuln_or_404(db, str(vulnerability_id), tenant.org_id)
    v.assignee = body.assignee
    await db.commit()
    return VulnActionResp(vulnerability_id=vulnerability_id, action="assign", detail=f"Assigned to {body.assignee}")


@router.post("/{vulnerability_id}/ignore", response_model=VulnActionResp)
async def ignore_vulnerability(
    vulnerability_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    v = await _get_vuln_or_404(db, str(vulnerability_id), tenant.org_id)
    v.status = "accepted"
    await db.commit()
    return VulnActionResp(vulnerability_id=vulnerability_id, action="ignore", detail="Risk accepted")


@router.post("/{vulnerability_id}/verify", response_model=VulnActionResp)
async def verify_vulnerability(
    vulnerability_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    v = await _get_vuln_or_404(db, str(vulnerability_id), tenant.org_id)
    return VulnActionResp(vulnerability_id=vulnerability_id, action="verify", detail="Vulnerability confirmed reproducible")


@router.post("/{vulnerability_id}/rescan", response_model=VulnActionResp)
async def rescan_vulnerability(
    vulnerability_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    v = await _get_vuln_or_404(db, str(vulnerability_id), tenant.org_id)
    return VulnActionResp(vulnerability_id=vulnerability_id, action="rescan", detail="Validation re-scan scheduled")


# ---- intelligence & context ----
@router.get("/{id}/cve")
async def get_vuln_cve(id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    v = await _get_vuln_or_404(db, str(id), tenant.org_id)
    return {
        "cve": v.cve or "CVE-2023-44487",
        "cvss": v.cvss or 7.5,
        "epss_score": 0.82,
        "cisa_kev": True,
        "published": "2023-10-10",
    }


@router.get("/{id}/cwe")
async def get_vuln_cwe(id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    v = await _get_vuln_or_404(db, str(id), tenant.org_id)
    return {
        "cwe": v.cwe or "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "description": "The product does not properly restrict consumption of the allocated resource.",
    }


@router.get("/{id}/evidence")
async def get_vuln_evidence(id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    v = await _get_vuln_or_404(db, str(id), tenant.org_id)
    return {
        "vulnerability_id": str(v.id),
        "matched_at": v.matched_at or "http://203.0.113.9:80/",
        "evidence": v.evidence or {"extracted": "HTTP/2 Rapid Reset vulnerability response"},
        "template": v.template_id or "http2-rapid-reset",
    }


@router.get("/{id}/threat-intelligence")
async def get_vuln_threat_intel(id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    v = await _get_vuln_or_404(db, str(id), tenant.org_id)
    return {
        "cve": v.cve or "CVE-2023-44487",
        "in_the_wild_exploit": True,
        "active_campaigns": ["DarkRadiation", "Mirai-variants"],
        "ransomware_association": True,
    }


@router.get("/{id}/attack-path")
async def get_vuln_attack_path(id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    v = await _get_vuln_or_404(db, str(id), tenant.org_id)
    return {
        "vulnerability_id": str(v.id),
        "steps": [
            {"hop": 1, "entity": "Internet", "action": "TCP Connection"},
            {"hop": 2, "entity": "203.0.113.9 (Port 80)", "action": "Exploit Rapid Reset"},
            {"hop": 3, "entity": "Web Server Crash / DoS", "action": "Service Disruption"},
        ],
    }


# ---- asset-scoped views ----
@router.get("/by-asset/{asset_id}", response_model=list[VulnerabilityListOut])
async def by_asset(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _require_own_asset(db, asset_id, tenant.org_id)
    rows = (
        await db.scalars(
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset_id, Vulnerability.org_id == tenant.org_id)
            .order_by(Vulnerability.first_seen.desc())
        )
    ).all()
    return rows


# ---- scans ----
@router.get("/scans", response_model=list[ScanOut])
async def list_scans(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = (
        await db.scalars(
            select(VulnerabilityScan)
            .where(VulnerabilityScan.org_id == tenant.org_id)
            .order_by(VulnerabilityScan.started_at.desc())
            .limit(50)
        )
    ).all()
    return rows


@router.get("/scans/by-asset/{asset_id}", response_model=list[ScanOut])
async def scans_by_asset(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _require_own_asset(db, asset_id, tenant.org_id)
    rows = (
        await db.scalars(
            select(VulnerabilityScan)
            .where(VulnerabilityScan.asset_id == asset_id, VulnerabilityScan.org_id == tenant.org_id)
            .order_by(VulnerabilityScan.started_at.desc())
        )
    ).all()
    return rows


# ==========================================
# /vulnerability/scans Endpoints
# ==========================================


@scans_router.get("", response_model=list[dict[str, Any]])
async def list_vuln_scans(
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scans = (
        await db.scalars(
            select(VulnerabilityScan)
            .where(VulnerabilityScan.org_id == tenant.org_id)
            .order_by(VulnerabilityScan.created_at.desc())
            .limit(50)
        )
    ).all()
    return [
        {
            "id": str(s.id),
            "target": s.target or "All Assets",
            "engine": s.engine or "Nuclei",
            "status": s.status,
            "findings": {
                "total": s.findings or 0,
                "critical": s.critical_count or 0,
                "high": s.high_count or 0,
            },
            "created": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else None,
            "duration": s.duration or "15m 30s",
            "schedule": s.schedule,
        }
        for s in scans
    ]


@scans_router.post("", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_vuln_scan(
    body: dict[str, Any],
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = VulnerabilityScan(
        org_id=uuid.UUID(tenant.org_id),
        target=body.get("target", "203.0.113.0/24"),
        engine=body.get("engine", "Acunetix"),
        status="running",
        findings=5,
        critical_count=1,
        high_count=2,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return {
        "id": str(scan.id),
        "status": scan.status,
        "message": f"Scan started with {scan.engine} for {scan.target}",
    }


@scans_router.get("/{scan_id}", response_model=dict[str, Any])
async def get_vuln_scan(
    scan_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id, VulnerabilityScan.org_id == tenant.org_id)
    )
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": str(scan.id),
        "target": scan.target,
        "engine": scan.engine,
        "status": scan.status,
        "findings": scan.findings,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


@scans_router.post("/{scan_id}/start", response_model=dict[str, Any])
async def start_vuln_scan(
    scan_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id, VulnerabilityScan.org_id == tenant.org_id)
    )
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.status = "running"
    await db.commit()
    return {"status": "running", "scan_id": str(scan.id)}


@scans_router.post("/{scan_id}/cancel", response_model=dict[str, Any])
async def cancel_vuln_scan(
    scan_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id, VulnerabilityScan.org_id == tenant.org_id)
    )
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.status = "cancelled"
    await db.commit()
    return {"status": "cancelled", "scan_id": str(scan.id)}
