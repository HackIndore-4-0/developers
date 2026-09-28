import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.factory import crud_router
from app.deps import Tenant, get_tenant, require_roles
from app.models.security import Asset, Exposure, ExposureEvent, utcnow
from app.schemas.intelligence import ExposureCreate, ExposureEventOut, ExposureListOut, ExposureOut, ExposureUpdate

router = APIRouter(prefix="/exposures", tags=["Exposures"])

factory_router = crud_router(
    Exposure,
    schemas={"list": ExposureListOut, "get": ExposureOut, "create": ExposureCreate, "update": ExposureUpdate},
    search_columns=[Exposure.affected_identity, Exposure.source, Exposure.domain],
    prefix="/exposures",
    allowed_methods=("list", "get", "create", "update", "delete"),
)


async def _exp_or_404(db: AsyncSession, exp_id: str, org_id: str) -> Exposure:
    e = await db.scalar(select(Exposure).where(Exposure.id == exp_id, Exposure.org_id == org_id))
    if not e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    return e


# ---------- Specialized Category Filters ----------


@router.get("/credentials", response_model=list[ExposureListOut])
async def get_credentials(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "credential").limit(50))
    return rows.all()


@router.get("/emails", response_model=list[ExposureListOut])
async def get_emails(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "email").limit(50))
    return rows.all()


@router.get("/passwords", response_model=list[ExposureListOut])
async def get_passwords(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "password").limit(50))
    return rows.all()


@router.get("/api-keys", response_model=list[ExposureListOut])
async def get_api_keys(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "api_key").limit(50))
    return rows.all()


@router.get("/tokens", response_model=list[ExposureListOut])
async def get_tokens(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "token").limit(50))
    return rows.all()


@router.get("/source-code", response_model=list[ExposureListOut])
async def get_source_code_leaks(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "source_code").limit(50))
    return rows.all()


@router.get("/stealer-logs", response_model=list[ExposureListOut])
async def get_stealer_logs(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "stealer_log").limit(50))
    return rows.all()


@router.get("/breaches", response_model=list[ExposureListOut])
async def get_breaches(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.type == "breach").limit(50))
    return rows.all()


# ---------- Search Endpoints ----------


@router.post("/search", response_model=list[ExposureListOut])
async def search(body: dict, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    q = body.get("q")
    category = body.get("category") or body.get("type")
    if not q and not category:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Provide q or category")

    stmt = select(Exposure).where(Exposure.org_id == tenant.org_id)
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                Exposure.affected_identity.ilike(pattern),
                Exposure.source.ilike(pattern),
                Exposure.domain.ilike(pattern),
            )
        )
    if category and category != "all":
        stmt = stmt.where(Exposure.type == category)
    stmt = stmt.order_by(Exposure.first_seen.desc()).limit(100)
    rows = (await db.scalars(stmt)).all()
    return rows


@router.post("/search/domain", response_model=list[ExposureListOut])
async def search_domain(body: dict[str, str], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    domain = body.get("domain", "")
    stmt = select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.domain.ilike(f"%{domain}%")).limit(50)
    return (await db.scalars(stmt)).all()


@router.post("/search/email", response_model=list[ExposureListOut])
async def search_email(body: dict[str, str], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    email = body.get("email", "")
    stmt = select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.affected_identity.ilike(f"%{email}%")).limit(50)
    return (await db.scalars(stmt)).all()


@router.post("/search/username", response_model=list[ExposureListOut])
async def search_username(body: dict[str, str], tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    username = body.get("username", "")
    stmt = select(Exposure).where(Exposure.org_id == tenant.org_id, Exposure.affected_identity.ilike(f"%{username}%")).limit(50)
    return (await db.scalars(stmt)).all()


# ---------- Details, Timeline & Intelligence ----------


@router.get("/events/{exp_id}", response_model=list[ExposureEventOut])
@router.get("/{exp_id}/timeline", response_model=list[ExposureEventOut])
async def events(exp_id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    await _exp_or_404(db, exp_id, tenant.org_id)
    rows = (
        await db.scalars(
            select(ExposureEvent).where(ExposureEvent.exposure_id == exp_id).order_by(ExposureEvent.occurred_at)
        )
    ).all()
    return rows


@router.get("/{id}/evidence")
async def get_exposure_evidence(id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    e = await _exp_or_404(db, id, tenant.org_id)
    return {
        "exposure_id": str(e.id),
        "mask": e.mask,
        "evidence": e.evidence or {"sample": "Sensitive token hash observed in public repository dump"},
        "source": e.source,
    }


@router.get("/{id}/source")
async def get_exposure_source(id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    e = await _exp_or_404(db, id, tenant.org_id)
    return {
        "exposure_id": str(e.id),
        "source": e.source,
        "first_seen": e.first_seen.isoformat(),
        "origin_type": "Dark Web Forum / Stealer Log Dump",
    }


@router.get("/{id}/related-assets")
async def get_exposure_related_assets(id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    e = await _exp_or_404(db, id, tenant.org_id)
    assets = await db.scalars(select(Asset).where(Asset.org_id == tenant.org_id, Asset.domain == e.domain).limit(5))
    return [
        {"id": str(a.id), "hostname": a.hostname, "ip": a.ip, "criticality": a.criticality}
        for a in assets.all()
    ]


@router.get("/{id}/risk")
async def get_exposure_risk(id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    e = await _exp_or_404(db, id, tenant.org_id)
    return {
        "exposure_id": str(e.id),
        "severity": e.severity,
        "impact_score": 8.5 if e.severity == "critical" else 6.0,
        "mitigation_priority": "Immediate",
    }


@router.patch("/{exp_id}/status", response_model=ExposureOut)
async def set_status(
    exp_id: str,
    body: dict,
    tenant: Tenant = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    e = await _exp_or_404(db, exp_id, tenant.org_id)
    new = body.get("status")
    allowed = {"open", "acknowledged", "resolved"}
    if new not in allowed:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid status")
    e.status = new
    e.updated_at = utcnow()
    db.add(ExposureEvent(exposure_id=e.id, kind=new, description=f"Status changed to {new}"))
    await db.commit()
    await db.refresh(e)
    return e
