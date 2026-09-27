import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import CodeRepository, SecretFinding
from app.schemas.domain import CodeRepoCreate, CodeRepoOut, SecretFindingOut

router = APIRouter(tags=["Code Repositories & Secrets"])


# ---------- Code Repositories ----------


@router.get("/code-repositories", response_model=list[CodeRepoOut])
async def list_repositories(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    stmt = (
        select(CodeRepository)
        .where(CodeRepository.org_id == tenant.org.id)
        .order_by(CodeRepository.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("/code-repositories", response_model=CodeRepoOut, status_code=status.HTTP_201_CREATED)
async def create_repository(
    body: CodeRepoCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    repo = CodeRepository(
        org_id=tenant.org.id,
        name=body.name,
        provider=body.provider,
        url=body.url,
        branch=body.branch,
        owner=body.owner,
        status="connected",
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)
    return repo


@router.get("/code-repositories/{repo_id}", response_model=CodeRepoOut)
async def get_repository(
    repo_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    repo = await db.scalar(
        select(CodeRepository).where(CodeRepository.id == repo_id, CodeRepository.org_id == tenant.org.id)
    )
    if not repo:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Repository not found")
    return repo


@router.post("/code-repositories/{repo_id}/scan", response_model=dict[str, Any])
async def scan_repository(
    repo_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    repo = await db.scalar(
        select(CodeRepository).where(CodeRepository.id == repo_id, CodeRepository.org_id == tenant.org.id)
    )
    if not repo:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Repository not found")
    repo.status = "scanning"
    repo.last_scan = datetime.now(timezone.utc)

    # Seed sample secret finding for demonstration
    finding = SecretFinding(
        org_id=tenant.org.id,
        repo_id=repo.id,
        secret_type="aws_secret_key",
        description="AWS Access Key ID exposed in repository",
        file_path="config/aws.env",
        line_number=14,
        author="dev@aurora.ai",
        raw_preview="AKIAIOSFODNN7EXAMPLE...",
        status="open",
        severity="critical",
    )
    db.add(finding)
    repo.secrets_count += 1
    repo.status = "connected"
    await db.commit()
    return {"status": "ok", "message": f"Scan completed for {repo.name}", "secrets_found": 1}


@router.get("/code-repositories/{repo_id}/findings", response_model=list[SecretFindingOut])
async def get_repository_findings(
    repo_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    findings = await db.scalars(
        select(SecretFinding).where(SecretFinding.repo_id == repo_id, SecretFinding.org_id == tenant.org.id)
    )
    return findings.all()


# ---------- Secrets ----------


@router.get("/secrets", response_model=list[SecretFindingOut])
async def list_secrets(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    stmt = (
        select(SecretFinding)
        .where(SecretFinding.org_id == tenant.org.id)
        .order_by(SecretFinding.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.get("/secrets/{secret_id}", response_model=SecretFindingOut)
async def get_secret(
    secret_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    secret = await db.scalar(
        select(SecretFinding).where(SecretFinding.id == secret_id, SecretFinding.org_id == tenant.org.id)
    )
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Secret not found")
    return secret


@router.post("/secrets/{secret_id}/revoke", response_model=dict[str, Any])
async def revoke_secret(
    secret_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    secret = await db.scalar(
        select(SecretFinding).where(SecretFinding.id == secret_id, SecretFinding.org_id == tenant.org.id)
    )
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Secret not found")
    secret.status = "revoked"
    await db.commit()
    return {"status": "ok", "message": "Secret marked as revoked"}


@router.post("/secrets/{secret_id}/resolve", response_model=dict[str, Any])
async def resolve_secret(
    secret_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    secret = await db.scalar(
        select(SecretFinding).where(SecretFinding.id == secret_id, SecretFinding.org_id == tenant.org.id)
    )
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Secret not found")
    secret.status = "resolved"
    await db.commit()
    return {"status": "ok", "message": "Secret marked as resolved"}
