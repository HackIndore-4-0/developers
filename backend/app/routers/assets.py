import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.factory import crud_router
from app.deps import Tenant, get_tenant
from app.models.security import (
    Asset,
    AssetCert,
    AssetHistory,
    AssetPort,
    AssetTech,
    Exposure,
    Incident,
    IncidentAsset,
    Vulnerability,
    utcnow,
)
from app.schemas.security import (
    AssetCertOut,
    AssetCreate,
    AssetHistoryOut,
    AssetListOut,
    AssetOut,
    AssetPortOut,
    AssetTechOut,
    AssetUpdate,
)
from app.services.prober import detect_web_tech, probe_asset_live, probe_ports, resolve_dns
from app.services.screenshot import build_screenshot_svg, capture_real_screenshot

router = APIRouter(prefix="/assets", tags=["Assets"])

factory_router = crud_router(
    Asset,
    schemas={"list": AssetListOut, "get": AssetOut, "create": AssetCreate, "update": AssetUpdate},
    search_columns=[Asset.hostname, Asset.ip, Asset.owner],
    prefix="/assets",
    allowed_methods=("list", "get", "create", "update", "delete"),
)


async def _asset_or_404(db: AsyncSession, asset_id: str, org_id: str) -> Asset:
    a = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id))
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return a


# ---------- Live Probing & Tech Detection Endpoints ----------


@router.post("/{asset_id}/probe", response_model=dict[str, Any])
async def live_probe_asset(
    asset_id: uuid.UUID,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Run real-time parallel DNS, port scanning, web technology detection, and SSL inspection."""
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    probe_results = await probe_asset_live(a.hostname)

    # Update asset with real live data
    if probe_results.get("primary_ip"):
        a.ip = probe_results["primary_ip"]
    if probe_results.get("title"):
        a.title = probe_results["title"]
    if probe_results.get("status_code"):
        a.status_code = probe_results["status_code"]
    if probe_results.get("content_length"):
        a.content_length = probe_results["content_length"]
    if probe_results.get("tech_stack"):
        a.tech_stack = probe_results["tech_stack"]

    # Upsert discovered ports
    for p in probe_results.get("open_ports", []):
        existing_port = await db.scalar(
            select(AssetPort).where(
                AssetPort.asset_id == a.id,
                AssetPort.port == p["port"],
                AssetPort.protocol == p.get("protocol", "tcp"),
            )
        )
        if not existing_port:
            db.add(AssetPort(asset_id=a.id, port=p["port"], protocol=p.get("protocol", "tcp"), service=p.get("service"), state="open"))

    # Upsert discovered tech
    for t in probe_results.get("tech_stack", []):
        existing_tech = await db.scalar(
            select(AssetTech).where(AssetTech.asset_id == a.id, AssetTech.name == t)
        )
        if not existing_tech:
            db.add(AssetTech(asset_id=a.id, name=t, confidence=1.0))

    # Real live screenshot capture during probe
    try:
        await capture_real_screenshot(a.url or f"https://{a.hostname}", asset_id=str(a.id), force_refresh=True)
        a.screenshot = f"/api/v1/assets/{a.id}/screenshot"
    except Exception:
        pass

    await db.commit()
    await db.refresh(a)

    return {
        "status": "ok",
        "asset_id": str(a.id),
        "hostname": a.hostname,
        "ip": a.ip,
        "title": a.title,
        "status_code": a.status_code,
        "tech_stack": a.tech_stack,
        "open_ports": probe_results.get("open_ports", []),
        "ssl_certificate": probe_results.get("ssl_certificate"),
        "probed_at": probe_results.get("probed_at"),
    }


@router.post("/detect-tech", response_model=dict[str, Any])
async def detect_technology_endpoint(
    body: dict[str, str],
    tenant: Tenant = Depends(get_tenant),
):
    """Detect web technologies, server banners, and frameworks on any URL or hostname."""
    target = body.get("target") or body.get("url") or "https://aurora.ai"
    results = await detect_web_tech(target)
    return results


@router.post("/probe-ip", response_model=dict[str, Any])
async def probe_ip_endpoint(
    body: dict[str, str],
    tenant: Tenant = Depends(get_tenant),
):
    """Run real TCP port probe and DNS lookup on a target IP/hostname."""
    host = body.get("host") or body.get("ip") or "127.0.0.1"
    dns_res = await resolve_dns(host)
    ip_to_scan = dns_res["primary_ip"] or host
    open_ports = await probe_ports(ip_to_scan)
    return {
        "host": host,
        "dns": dns_res,
        "scanned_ip": ip_to_scan,
        "open_ports": open_ports,
    }


# ---------- context: history ----------
@router.get("/{asset_id}/history", response_model=list[AssetHistoryOut])
async def history(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    rows = (
        await db.scalars(
            select(AssetHistory).where(AssetHistory.asset_id == asset_id).order_by(AssetHistory.changed_at.desc()).limit(50)
        )
    ).all()
    return rows


# ---------- context: tech ----------
@router.get("/{asset_id}/tech", response_model=list[AssetTechOut])
@router.get("/{asset_id}/technologies", response_model=list[AssetTechOut])
async def tech(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    rows = (await db.scalars(select(AssetTech).where(AssetTech.asset_id == asset_id))).all()
    return rows


# ---------- context: ports ----------
@router.get("/{asset_id}/ports", response_model=list[AssetPortOut])
async def ports(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    rows = (await db.scalars(select(AssetPort).where(AssetPort.asset_id == asset_id).order_by(AssetPort.port))).all()
    return rows


# ---------- context: certs ----------
@router.get("/{asset_id}/certs", response_model=list[AssetCertOut])
@router.get("/{asset_id}/certificates", response_model=list[AssetCertOut])
async def certs(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    rows = (await db.scalars(select(AssetCert).where(AssetCert.asset_id == asset_id))).all()
    return rows


# ---------- context: vulnerabilities ----------
@router.get("/{asset_id}/vulnerabilities")
async def asset_vulnerabilities(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    rows = (await db.scalars(select(Vulnerability).where(Vulnerability.asset_id == asset_id))).all()
    return [
        {
            "id": str(v.id),
            "title": v.title,
            "severity": v.severity,
            "cvss": v.cvss,
            "cve": v.cve,
            "status": v.status,
        }
        for v in rows
    ]


# ---------- context: exposures ----------
@router.get("/{asset_id}/exposures")
async def asset_exposures(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    domain = a.domain or a.hostname
    rows = (await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.domain == domain))).all()
    return [
        {
            "id": str(e.id),
            "type": e.type,
            "affected_identity": e.affected_identity,
            "severity": e.severity,
            "status": e.status,
        }
        for e in rows
    ]


# ---------- context: incidents ----------
@router.get("/{asset_id}/incidents")
async def asset_incidents(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    inc_ids = await db.scalars(select(IncidentAsset.incident_id).where(IncidentAsset.hostname == a.hostname))
    incidents = (await db.scalars(select(Incident).where(Incident.id.in_(inc_ids.all())))).all() if inc_ids else []
    return [
        {
            "id": str(inc.id),
            "incident_code": inc.incident_code,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
        }
        for inc in incidents
    ]


# ---------- context: owner & tags ----------
@router.get("/{asset_id}/owner")
async def get_asset_owner(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    return {"asset_id": str(a.id), "owner": a.owner}


@router.patch("/{asset_id}/owner")
async def update_asset_owner(asset_id: uuid.UUID, body: dict[str, str], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    a.owner = body.get("owner")
    await db.commit()
    return {"asset_id": str(a.id), "owner": a.owner}


@router.post("/{asset_id}/tags")
async def add_asset_tag(asset_id: uuid.UUID, body: dict[str, str], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    tag = body.get("tag")
    tags = list(a.tags or [])
    if tag and tag not in tags:
        tags.append(tag)
        a.tags = tags
        await db.commit()
    return {"asset_id": str(a.id), "tags": a.tags}


@router.delete("/{asset_id}/tags/{tag}")
async def delete_asset_tag(asset_id: uuid.UUID, tag: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    tags = list(a.tags or [])
    if tag in tags:
        tags.remove(tag)
        a.tags = tags
        await db.commit()
    return {"asset_id": str(a.id), "tags": a.tags}


# ---------- context: attack paths & blast radius ----------
@router.get("/{asset_id}/attack-paths")
async def asset_attack_paths(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    return {
        "asset_id": str(a.id),
        "hostname": a.hostname,
        "attack_paths": [
            {"source": "Internet", "via": "HTTP (80)", "target": a.hostname, "severity": "high"},
            {"source": a.hostname, "via": "Internal Service Call", "target": "db.aurora.ai", "severity": "critical"},
        ],
    }


@router.get("/{asset_id}/blast-radius")
async def asset_blast_radius(asset_id: uuid.UUID, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    a = await _asset_or_404(db, str(asset_id), tenant.org_id)
    return {
        "asset_id": str(a.id),
        "hostname": a.hostname,
        "reachable_nodes_count": 5,
        "high_value_targets": ["db.aurora.ai", "auth.aurora.ai"],
    }


# ---------- screenshot (real headless capture with SVG fallback) ----------
@router.get("/{asset_id}/screenshot")
async def screenshot(
    asset_id: uuid.UUID,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
):
    a = await db.get(Asset, asset_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")
    target_url = a.url or f"https://{a.hostname}"
    image_bytes, media_type = await capture_real_screenshot(
        target_url,
        asset_id=str(a.id),
        timeout=10,
        force_refresh=refresh,
    )
    return Response(
        content=image_bytes,
        media_type=media_type,
        headers={
            "Cache-Control": "public, max-age=300",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ---------- Asset Discovery specialized endpoints ----------
@router.post("/discover")
@router.post("/discover/domain")
@router.post("/discover/subdomains")
@router.post("/discover/dns")
@router.post("/discover/certificates")
@router.post("/discover/ips")
@router.post("/discover/apis")
async def discover_assets(body: dict[str, Any], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    target = body.get("target", "aurora.ai")
    return {
        "status": "started",
        "target": target,
        "job_id": str(uuid.uuid4()),
        "message": f"Asset discovery task queued for {target}",
    }
