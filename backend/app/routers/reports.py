import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import ReportRecord
from app.schemas.domain import ReportCreate, ReportOut

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("", response_model=list[ReportOut])
async def list_reports(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    stmt = (
        select(ReportRecord)
        .where(ReportRecord.org_id == tenant.org.id)
        .order_by(ReportRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def create_report(
    body: ReportCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    report = ReportRecord(
        org_id=tenant.org.id,
        title=body.title,
        type=body.type,
        format=body.format,
        status="generated",
        file_size="2.4 MB",
        download_url=f"/api/v1/reports/download/{uuid.uuid4()}",
        created_by=tenant.user.name or tenant.user.email,
        parameters=body.parameters,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/{id}", response_model=ReportOut)
async def get_report(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    report = await db.scalar(
        select(ReportRecord).where(ReportRecord.id == id, ReportRecord.org_id == tenant.org.id)
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.post("/{id}/generate", response_model=ReportOut)
async def generate_report_by_id(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    report = await db.scalar(
        select(ReportRecord).where(ReportRecord.id == id, ReportRecord.org_id == tenant.org.id)
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report not found")
    report.status = "generated"
    report.file_size = "2.8 MB"
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/{id}/download")
async def download_report(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    report = await db.scalar(
        select(ReportRecord).where(ReportRecord.id == id, ReportRecord.org_id == tenant.org.id)
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report not found")
    csv_content = (
        f"# SignalThread Security Report\n"
        f"Title,{report.title}\n"
        f"Type,{report.type}\n"
        f"Generated At,{report.created_at.isoformat()}\n"
        f"Organization,{tenant.org.name}\n"
    )
    return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=report-{id}.csv"})


@router.post("/executive", response_model=ReportOut)
async def generate_executive_report(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    req = ReportCreate(title=f"Executive Posture Summary - {datetime.now(timezone.utc).strftime('%B %Y')}", type="executive")
    return await create_report(body=req, tenant=tenant, db=db)


@router.post("/security", response_model=ReportOut)
async def generate_security_report(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    req = ReportCreate(title=f"Technical Threat & Vulnerability Audit - {datetime.now(timezone.utc).strftime('%B %Y')}", type="security")
    return await create_report(body=req, tenant=tenant, db=db)


@router.post("/incident", response_model=ReportOut)
async def generate_incident_report(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    req = ReportCreate(title=f"Incident Post-Mortem & Timeline Report - {datetime.now(timezone.utc).strftime('%B %Y')}", type="incident")
    return await create_report(body=req, tenant=tenant, db=db)


@router.post("/compliance", response_model=ReportOut)
async def generate_compliance_report(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    req = ReportCreate(title=f"SOC 2 / ISO 27001 Continuous Exposure Assessment", type="compliance")
    return await create_report(body=req, tenant=tenant, db=db)
