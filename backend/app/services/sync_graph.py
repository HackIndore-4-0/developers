"""Best-effort mirror of procedural PG data into the Neo4j security graph."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Organization
from app.models.security import Asset, Exposure, Vulnerability
from app.services import graph


async def sync_org(db: AsyncSession, org_id: str) -> dict:
    org = await db.get(Organization, org_id)
    if not org:
        return {"synced": False, "error": "org not found"}

    await graph.ensure_schema()
    await graph.upsert_org(str(org.id), org.name)

    assets = (await db.scalars(select(Asset).where(Asset.org_id == org.id))).all()
    for a in assets:
        await graph.upsert_asset(str(a.org_id), str(a.id), a.hostname, a.criticality, a.type)

    vulns = (await db.scalars(select(Vulnerability).where(Vulnerability.org_id == org.id))).all()
    for v in vulns:
        await graph.upsert_vuln(str(v.org_id), str(v.asset_id), str(v.id), v.title, v.severity, v.cve)

    exps = (await db.scalars(select(Exposure).where(Exposure.org_id == org.id))).all()
    for e in exps:
        await graph.upsert_exposure(str(e.org_id), str(e.id), str(e.affected_identity), e.type, e.severity)

    return {"synced": True, "assets": len(assets), "vulns": len(vulns), "exposures": len(exps)}