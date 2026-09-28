import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import MitreTechnique, ThreatActor, ThreatCampaign, ThreatIOC, ThreatMalware
from app.schemas.domain import (
    MitreTechniqueOut,
    ThreatActorOut,
    ThreatCampaignOut,
    ThreatIOCOut,
    ThreatMalwareOut,
)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# ---------- IOC Enrichment ----------


@router.post("/enrich/ip", response_model=ThreatIOCOut)
async def enrich_ip(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    ip = body.get("ip", "203.0.113.42")
    ioc = await db.scalar(
        select(ThreatIOC).where(ThreatIOC.org_id == tenant.org.id, ThreatIOC.value == ip)
    )
    if not ioc:
        ioc = ThreatIOC(
            org_id=tenant.org.id,
            type="ip",
            value=ip,
            reputation="malicious" if ip.endswith(".42") else "suspicious",
            source="AlienVault OTX",
            tags=["C2", "Tor Exit Node", "Scanner"],
            asn="AS49339",
            country="Russia",
            owner="Relay Network LLC",
            malware=["Lockbit 3.0", "Conti"],
            campaigns=["Operation Blue"],
            ttps=["T1071.001", "T1562.004"],
            description="Active command-and-control IP associated with automated brute force scans.",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    return ioc


@router.post("/enrich/domain", response_model=ThreatIOCOut)
async def enrich_domain(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    domain = body.get("domain", "malware.badssl.com")
    ioc = await db.scalar(
        select(ThreatIOC).where(ThreatIOC.org_id == tenant.org.id, ThreatIOC.value == domain)
    )
    if not ioc:
        ioc = ThreatIOC(
            org_id=tenant.org.id,
            type="domain",
            value=domain,
            reputation="malicious" if "bad" in domain else "benign",
            source="VirusTotal",
            tags=["Phishing", "Malware Hosting"],
            malware=["TrickBot"],
            campaigns=["APT29"],
            ttps=["T1566.002"],
            description="Domain identified in malicious credential harvesting campaigns.",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    return ioc


@router.post("/enrich/hash", response_model=ThreatIOCOut)
async def enrich_hash(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    val = body.get("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ioc = await db.scalar(
        select(ThreatIOC).where(ThreatIOC.org_id == tenant.org.id, ThreatIOC.value == val)
    )
    if not ioc:
        ioc = ThreatIOC(
            org_id=tenant.org.id,
            type="hash",
            value=val,
            reputation="malicious",
            source="MalwareBazaar",
            tags=["Ransomware", "Payload"],
            malware=["LockBit"],
            description="SHA256 hash matching known encrypted malware payload binary.",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    return ioc


@router.post("/enrich/url", response_model=ThreatIOCOut)
async def enrich_url(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    url = body.get("url", "https://evil.com/payload.exe")
    ioc = await db.scalar(
        select(ThreatIOC).where(ThreatIOC.org_id == tenant.org.id, ThreatIOC.value == url)
    )
    if not ioc:
        ioc = ThreatIOC(
            org_id=tenant.org.id,
            type="url",
            value=url,
            reputation="malicious",
            source="URLhaus",
            tags=["Malware Download"],
            malware=["AgentTesla"],
            description="Direct link observed delivering second-stage infostealer.",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    return ioc


# ---------- IOCs & Intelligence Entities ----------


@router.get("/iocs", response_model=list[ThreatIOCOut])
async def list_iocs(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = (
        select(ThreatIOC)
        .where(ThreatIOC.org_id == tenant.org.id)
        .order_by(ThreatIOC.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.get("/iocs/{ioc_id}", response_model=ThreatIOCOut)
async def get_ioc(
    ioc_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    ioc = await db.scalar(
        select(ThreatIOC).where(ThreatIOC.id == ioc_id, ThreatIOC.org_id == tenant.org.id)
    )
    if not ioc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return ioc


@router.get("/actors", response_model=list[ThreatActorOut])
async def list_threat_actors(
    db: AsyncSession = Depends(get_db),
):
    actors = await db.scalars(select(ThreatActor).limit(50))
    return actors.all()


@router.get("/campaigns", response_model=list[ThreatCampaignOut])
async def list_threat_campaigns(
    db: AsyncSession = Depends(get_db),
):
    campaigns = await db.scalars(select(ThreatCampaign).limit(50))
    return campaigns.all()


@router.get("/malware", response_model=list[ThreatMalwareOut])
async def list_threat_malware(
    db: AsyncSession = Depends(get_db),
):
    malware = await db.scalars(select(ThreatMalware).limit(50))
    return malware.all()


@router.get("/mitre", response_model=list[MitreTechniqueOut])
async def list_mitre_techniques(
    db: AsyncSession = Depends(get_db),
):
    techniques = await db.scalars(select(MitreTechnique).limit(50))
    return techniques.all()


@router.get("/mitre/{technique_id}", response_model=MitreTechniqueOut)
async def get_mitre_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
):
    tech = await db.scalar(select(MitreTechnique).where(MitreTechnique.id == technique_id))
    if not tech:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Technique not found")
    return tech
