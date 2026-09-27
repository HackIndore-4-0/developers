import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import NetworkScan, NetworkScanHost, NetworkScanPort, NetworkScanService
from app.schemas.domain import (
    NetworkScanCreate,
    NetworkScanHostOut,
    NetworkScanOut,
    NetworkScanPortOut,
    NetworkScanServiceOut,
)

router = APIRouter(prefix="/network/scans", tags=["Network Scans"])


@router.get("", response_model=list[NetworkScanOut])
async def list_network_scans(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    stmt = (
        select(NetworkScan)
        .where(NetworkScan.org_id == tenant.org.id)
        .order_by(NetworkScan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("", response_model=NetworkScanOut, status_code=status.HTTP_201_CREATED)
async def create_network_scan(
    body: NetworkScanCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = NetworkScan(
        org_id=tenant.org.id,
        target=body.target,
        type=body.type,
        status="running",
        hosts_count=1,
        ports_count=10,
        services_count=3,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    # Create initial host/port/service findings
    host = NetworkScanHost(scan_id=scan.id, ip=body.target.split("/")[0], hostname="target.local", status="up")
    port1 = NetworkScanPort(scan_id=scan.id, ip=host.ip, port=80, protocol="tcp", service="http", state="open")
    port2 = NetworkScanPort(scan_id=scan.id, ip=host.ip, port=443, protocol="tcp", service="https", state="open")
    port3 = NetworkScanPort(scan_id=scan.id, ip=host.ip, port=22, protocol="tcp", service="ssh", state="open")
    srv = NetworkScanService(scan_id=scan.id, ip=host.ip, port=80, name="nginx", version="1.24.0", banner="nginx/1.24.0")

    db.add_all([host, port1, port2, port3, srv])
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=NetworkScanOut)
async def get_network_scan(
    scan_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(NetworkScan).where(NetworkScan.id == scan_id, NetworkScan.org_id == tenant.org.id)
    )
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=NetworkScanOut)
async def cancel_network_scan(
    scan_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(NetworkScan).where(NetworkScan.id == scan_id, NetworkScan.org_id == tenant.org.id)
    )
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    scan.status = "cancelled"
    scan.finished_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}/hosts", response_model=list[NetworkScanHostOut])
async def get_scan_hosts(
    scan_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(NetworkScan).where(NetworkScan.id == scan_id, NetworkScan.org_id == tenant.org.id)
    )
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    hosts = await db.scalars(select(NetworkScanHost).where(NetworkScanHost.scan_id == scan_id))
    return hosts.all()


@router.get("/{scan_id}/ports", response_model=list[NetworkScanPortOut])
async def get_scan_ports(
    scan_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(NetworkScan).where(NetworkScan.id == scan_id, NetworkScan.org_id == tenant.org.id)
    )
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    ports = await db.scalars(select(NetworkScanPort).where(NetworkScanPort.scan_id == scan_id))
    return ports.all()


@router.get("/{scan_id}/services", response_model=list[NetworkScanServiceOut])
async def get_scan_services(
    scan_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.scalar(
        select(NetworkScan).where(NetworkScan.id == scan_id, NetworkScan.org_id == tenant.org.id)
    )
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    services = await db.scalars(select(NetworkScanService).where(NetworkScanService.scan_id == scan_id))
    return services.all()
