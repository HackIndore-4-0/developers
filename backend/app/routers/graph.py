import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import Tenant, get_tenant, require_roles
from app.models.security import Asset
from app.services import graph, sync_graph

router = APIRouter(prefix="/graph", tags=["graph"])


@router.post("/sync")
async def sync(tenant: Tenant = Depends(require_roles("admin", "analyst")), db: AsyncSession = Depends(get_db)):
    return await sync_graph.sync_org(db, tenant.org_id)


async def _asset_or_404(db: AsyncSession, asset_id: str, org_id: str) -> Asset:
    a = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id))
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return a


@router.get("/overview")
async def overview(tenant: Tenant = Depends(get_tenant)):
    try:
        return await graph.org_summary(tenant.org_id)
    except Exception:  # noqa: BLE001
        return {"synced": False, "assets": 0, "vulns": 0, "exposures": 0, "nodes": [], "edges": []}


@router.get("/attack-path/{asset_id}")
async def attack_path(
    asset_id: uuid.UUID,
    target_id: uuid.UUID | None = None,
    depth: int = 4,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    if target_id:
        await _asset_or_404(db, str(target_id), tenant.org_id)
    try:
        paths = await graph.attack_path(tenant.org_id, str(asset_id), str(target_id) if target_id else None, depth)
        return {"paths": paths}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Graph unavailable: {e}") from e


@router.get("/blast-radius/{asset_id}")
async def blast_radius(
    asset_id: uuid.UUID,
    depth: int = 3,
    tenant: Tenant = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    await _asset_or_404(db, str(asset_id), tenant.org_id)
    try:
        return {"radius": await graph.blast_radius(tenant.org_id, str(asset_id), depth)}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Graph unavailable: {e}") from e