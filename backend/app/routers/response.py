import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import ResponseAction
from app.schemas.domain import (
    BlockIpReq,
    DisableUserReq,
    IsolateEndpointReq,
    ResponseActionCreate,
    ResponseActionOut,
    RevokeSessionReq,
    RevokeTokenReq,
)

router = APIRouter(tags=["Response Actions"])


@router.get("/response/actions", response_model=list[ResponseActionOut])
async def list_response_actions(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = select(ResponseAction).where(ResponseAction.org_id == tenant.org.id)
    if status_filter:
        stmt = stmt.where(ResponseAction.status == status_filter)
    stmt = stmt.order_by(ResponseAction.requested_at.desc()).limit(limit).offset(offset)
    result = await db.scalars(stmt)
    return result.all()


@router.post("/response/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
async def create_response_action(
    body: ResponseActionCreate,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type=body.type,
        target=body.target,
        description=body.description,
        incident_id=body.incident_id,
        status="pending",
        requested_by=tenant.user.name or tenant.user.email,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/response/actions/{action_id}", response_model=ResponseActionOut)
async def get_response_action(
    action_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = await db.scalar(
        select(ResponseAction).where(ResponseAction.id == action_id, ResponseAction.org_id == tenant.org.id)
    )
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Action not found")
    return action


@router.post("/response/actions/{id}/approve", response_model=ResponseActionOut)
async def approve_response_action(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = await db.scalar(
        select(ResponseAction).where(ResponseAction.id == id, ResponseAction.org_id == tenant.org.id)
    )
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Action not found")
    action.status = "approved"
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/actions/{id}/reject", response_model=ResponseActionOut)
async def reject_response_action(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = await db.scalar(
        select(ResponseAction).where(ResponseAction.id == id, ResponseAction.org_id == tenant.org.id)
    )
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Action not found")
    action.status = "rejected"
    action.result = "Rejected by analyst"
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/actions/{id}/execute", response_model=ResponseActionOut)
async def execute_response_action(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = await db.scalar(
        select(ResponseAction).where(ResponseAction.id == id, ResponseAction.org_id == tenant.org.id)
    )
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Action not found")
    action.status = "completed"
    action.executed_at = datetime.now(timezone.utc)
    action.result = "Success"
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/block-ip", response_model=ResponseActionOut)
async def block_ip(
    body: BlockIpReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type="Block IP",
        target=body.ip,
        description=body.reason,
        status="completed",
        result="Success",
        requested_by=tenant.user.name or tenant.user.email,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/revoke-session", response_model=ResponseActionOut)
async def revoke_session_action(
    body: RevokeSessionReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type="Revoke Session",
        target=body.session_id,
        description=body.reason,
        status="completed",
        result="Success",
        requested_by=tenant.user.name or tenant.user.email,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/revoke-token", response_model=ResponseActionOut)
async def revoke_token_action(
    body: RevokeTokenReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type="Revoke Token",
        target=body.token[:12] + "...",
        description=body.reason,
        status="completed",
        result="Success",
        requested_by=tenant.user.name or tenant.user.email,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/disable-user", response_model=ResponseActionOut)
async def disable_user_action(
    body: DisableUserReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type="Disable User",
        target=body.user_email,
        description=body.reason,
        status="completed",
        result="Success",
        requested_by=tenant.user.name or tenant.user.email,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/response/isolate-endpoint", response_model=ResponseActionOut)
async def isolate_endpoint_action(
    body: IsolateEndpointReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = ResponseAction(
        org_id=tenant.org.id,
        action_code=f"RA-{uuid.uuid4().hex[:4].upper()}",
        type="Isolate Endpoint",
        target=body.hostname,
        description=body.reason,
        status="completed",
        result="Success",
        requested_by=tenant.user.name or tenant.user.email,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/response/{id}/result", response_model=dict[str, Any])
async def get_response_action_result(
    id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    action = await db.scalar(
        select(ResponseAction).where(ResponseAction.id == id, ResponseAction.org_id == tenant.org.id)
    )
    if not action:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Action not found")
    return {
        "id": str(action.id),
        "status": action.status,
        "result": action.result or "Pending execution",
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
    }
