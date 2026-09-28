import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import get_current_user, get_tenant, require_roles
from app.models import Organization, OrganizationMember, User, utcnow
from app.schemas import MemberOut, MemberUpdate, OrgCreate, OrgOut, OrgUpdate, RoleOut

router = APIRouter(prefix="/organizations", tags=["organizations"])

ROLES = ("admin", "analyst", "viewer")


@router.post("", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
async def create_org(
    body: OrgCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.scalar(select(Organization).where(Organization.slug == body.slug))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Organization slug already exists")

    org = Organization(name=body.name, slug=body.slug, description=body.description)
    db.add(org)
    await db.flush()

    db.add(OrganizationMember(org_id=org.id, user_id=user.id, role="admin"))
    await db.commit()
    await db.refresh(org)
    return org


@router.get("", response_model=list[OrgOut])
async def list_orgs(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    orgs = list(
        (
            await db.scalars(
                select(Organization)
                .join(OrganizationMember, OrganizationMember.org_id == Organization.id)
                .where(OrganizationMember.user_id == user.id)
            )
        ).all()
    )
    return orgs


@router.get("/{slug}", response_model=OrgOut)
async def get_org(
    slug: str,
    tenant=Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    org = await db.scalar(select(Organization).where(Organization.slug == slug, Organization.id == tenant.org_id))
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


@router.patch("/{slug}", response_model=OrgOut)
async def update_org(
    slug: str,
    body: OrgUpdate,
    tenant=Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
):
    org = await db.scalar(select(Organization).where(Organization.slug == slug, Organization.id == tenant.org_id))
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    if body.name is not None:
        org.name = body.name
    if body.description is not None:
        org.description = body.description
    if body.logo_url is not None:
        org.logo_url = body.logo_url
    org.updated_at = utcnow()
    await db.commit()
    await db.refresh(org)
    return org


# ---------- Members ----------


@router.get("/{slug}/members", response_model=list[MemberOut])
async def list_members(
    slug: str,
    tenant=Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    await _org_or_404(db, slug, tenant.org_id)
    rows = list(
        (
            await db.execute(
                select(OrganizationMember, User.email, User.name)
                .join(User, User.id == OrganizationMember.user_id)
                .where(OrganizationMember.org_id == tenant.org_id)
            )
        ).all()
    )
    return [
        MemberOut(
            id=m.id, org_id=m.org_id, user_id=m.user_id, role=m.role, joined_at=m.joined_at, email=email, name=name
        )
        for m, email, name in rows
    ]


@router.post("/{slug}/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def add_member(
    slug: str,
    body: dict,
    tenant=Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
):
    await _org_or_404(db, slug, tenant.org_id)
    email = body.get("email")
    role = body.get("role", "viewer")
    if role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid role")
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="email required")

    user = await db.scalar(select(User).where(User.email == email))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No user with this email; registration/signup is not open in Phase 1")

    existing = await db.scalar(
        select(OrganizationMember).where(OrganizationMember.org_id == tenant.org_id, OrganizationMember.user_id == user.id)
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User is already a member")

    member = OrganizationMember(org_id=tenant.org_id, user_id=user.id, role=role)
    db.add(member)
    await db.commit()
    await db.refresh(member)

    return MemberOut(
        id=member.id, org_id=member.org_id, user_id=member.user_id, role=member.role, joined_at=member.joined_at,
        email=user.email, name=user.name,
    )


@router.patch("/{slug}/members/{user_id}", response_model=MemberOut)
async def update_member_role(
    slug: str,
    user_id: uuid.UUID,
    body: MemberUpdate,
    tenant=Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
):
    await _org_or_404(db, slug, tenant.org_id)
    if body.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    member = await db.scalar(
        select(OrganizationMember).where(OrganizationMember.org_id == tenant.org_id, OrganizationMember.user_id == user_id)
    )
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Member not found")

    if str(member.user_id) == tenant.user_id and body.role != "admin":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Cannot demote yourself")

    member.role = body.role
    await db.commit()
    await db.refresh(member)

    user = await db.get(User, member.user_id)
    return MemberOut(
        id=member.id, org_id=member.org_id, user_id=member.user_id, role=member.role, joined_at=member.joined_at,
        email=user.email, name=user.name,
    )


@router.delete("/{slug}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    slug: str,
    user_id: uuid.UUID,
    tenant=Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
):
    await _org_or_404(db, slug, tenant.org_id)
    if str(user_id) == tenant.user_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Cannot remove yourself")

    member = await db.scalar(
        select(OrganizationMember).where(OrganizationMember.org_id == tenant.org_id, OrganizationMember.user_id == user_id)
    )
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Member not found")

    await db.delete(member)
    await db.commit()


@router.get("/roles", response_model=list[RoleOut])
async def list_roles():
    return [
        RoleOut(name="admin", description="Full control: manage org, members, response approvals"),
        RoleOut(name="analyst", description="Create and run investigations, propose response actions"),
        RoleOut(name="viewer", description="Read-only access to all data"),
    ]


async def _org_or_404(db: AsyncSession, slug: str, org_id: str) -> Organization:
    org = await db.scalar(select(Organization).where(Organization.slug == slug, Organization.id == org_id))
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org