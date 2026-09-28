from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import Tenant, get_tenant, require_roles
from app.models.security import DiscoveryJob, utcnow
from app.schemas.security import DiscoveryJobOut, DiscoveryRunRequest
from app.services.discovery_run import get_job, run_discovery_job, job_to_result

router = APIRouter(prefix="/discovery", tags=["discovery"])


async def _run_background(job_id: str, org_id: str):
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        job = await db.get(DiscoveryJob, job_id)
        if job and str(job.org_id) == org_id:
            await run_discovery_job(db, job)


@router.post("/run", response_model=dict, status_code=status.HTTP_201_CREATED)
async def run_tool(
    body: DiscoveryRunRequest,
    background: BackgroundTasks,
    tenant: Tenant = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = DiscoveryJob(
        org_id=tenant.org_id,
        target=body.target,
        tool=body.tool,
        source=body.source,
        created_by=tenant.user_id,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    background.add_task(_run_background, str(job.id), tenant.org_id)
    return job_to_result(job)


@router.get("/jobs", response_model=list[dict])
async def list_jobs(tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    rows = (
        await db.scalars(
            select(DiscoveryJob)
            .where(DiscoveryJob.org_id == tenant.org_id)
            .order_by(DiscoveryJob.created_at.desc())
            .limit(50)
        )
    ).all()
    return [job_to_result(j) for j in rows]


@router.get("/jobs/{job_id}", response_model=dict)
async def get_job_(job_id: str, tenant: Tenant = Depends(get_tenant), db: AsyncSession = Depends(get_db)):
    job = await get_job(db, job_id, tenant.org_id)
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job_to_result(job)