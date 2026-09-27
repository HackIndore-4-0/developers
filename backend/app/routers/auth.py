import hashlib
import uuid
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.deps import get_current_user, get_token_claims
from app.models import Organization, OrganizationMember, Session, User, utcnow
from app.schemas import LoginRequest, MeOut, OrgSummary, RefreshRequest, TokenPair, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


def _hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _get_memberships(db: AsyncSession, user_id: uuid.UUID) -> list[OrganizationMember]:
    return list(
        (await db.scalars(select(OrganizationMember).where(OrganizationMember.user_id == user_id))).all()
    )


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == body.email))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    refresh_token = create_refresh_token(str(user.id))
    session = Session(
        user_id=user.id,
        refresh_token_hash=_hash_refresh(refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(session)
    await db.commit()

    # No org scope yet — user selects an org next (org-scoped access token issued on select).
    return TokenPair(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    session = await db.scalar(
        select(Session)
        .where(Session.refresh_token_hash == _hash_refresh(body.refresh_token))
        .where(Session.revoked_at.is_(None))
    )
    if not session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session revoked or not found")

    if session.expires_at <= utcnow():
        session.revoked_at = utcnow()
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    user = await db.get(User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User disabled")

    roles: list[str] = []
    org_id: str | None = None
    if session.org_id:
        membership = await db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user.id, OrganizationMember.org_id == session.org_id
            )
        )
        if membership:
            org_id = str(session.org_id)
            roles = [membership.role]

    new_refresh = create_refresh_token(str(user.id), org_id, roles)
    session.refresh_token_hash = _hash_refresh(new_refresh)
    await db.commit()

    return TokenPair(
        access_token=create_access_token(str(user.id), org_id, roles),
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    session = await db.scalar(select(Session).where(Session.refresh_token_hash == _hash_refresh(body.refresh_token)))
    if session:
        session.revoked_at = utcnow()
        await db.commit()


@router.post("/select-org", response_model=TokenPair)
async def select_org(body: dict, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    org_id = body.get("org_id")
    if not org_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="org_id required")

    try:
        uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid org_id")

    membership = await db.scalar(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id, OrganizationMember.org_id == org_id)
    )
    if not membership:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not a member of this organization")

    refresh_token = create_refresh_token(str(user.id), org_id, [membership.role])
    session = Session(
        user_id=user.id,
        org_id=org_id,
        refresh_token_hash=_hash_refresh(refresh_token),
        expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(session)
    await db.commit()

    return TokenPair(
        access_token=create_access_token(str(user.id), org_id, [membership.role]),
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=MeOut)
async def me(
    user: User = Depends(get_current_user),
    claims: dict = Depends(get_token_claims),
    db: AsyncSession = Depends(get_db),
):
    memberships = await _get_memberships(db, user.id)

    org_ids = [m.org_id for m in memberships]
    orgs: list[Organization] = []
    if org_ids:
        orgs = list((await db.scalars(select(Organization).where(Organization.id.in_(org_ids)))).all())

    # active org + roles come from the token's org claim (set at select-org / refresh),
    # re-confirmed against fresh membership rows.
    claimed_org = claims.get("org_id")
    active: OrgSummary | None = None
    roles: list[str] = []
    membership_by_org = {str(m.org_id): m for m in memberships}
    summaries = [OrgSummary(id=o.id, name=o.name, slug=o.slug) for o in orgs]
    for o in orgs:
        if claimed_org and str(o.id) == claimed_org and claimed_org in membership_by_org:
            active = OrgSummary(id=o.id, name=o.name, slug=o.slug)
            roles = [membership_by_org[claimed_org].role]
            break
    if active is None and summaries:
        active = summaries[0]
        roles = [membership_by_org[str(active.id)].role]

    return MeOut(user=UserOut.model_validate(user), active_org=active, organizations=summaries, roles=roles)