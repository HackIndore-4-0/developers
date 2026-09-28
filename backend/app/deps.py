import uuid
from types import SimpleNamespace

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token
from app.models import Organization, OrganizationMember, User

bearer_scheme = HTTPBearer(auto_error=True)

SUPERADMIN_EMAILS = {"admin@aurora.ai", "superadmin@signalthread.io"}


def _unauthorized(detail: str = "Invalid or expired credentials") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise _unauthorized()

    user = await db.get(User, payload.get("sub"))
    if not user or not user.is_active:
        raise _unauthorized("User is disabled or not found")
    return user


async def get_token_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise _unauthorized()
    return payload


class Tenant:
    """Org scoping is claims + fresh DB membership, never path params."""

    def __init__(self, org_id: str, role: str, user_id: str, user: User | None = None, org: Organization | None = None):
        self.org_id = org_id
        self.role = role
        self.user_id = user_id
        self._user_obj = user
        self._org_obj = org

    @property
    def is_superadmin(self) -> bool:
        if self.role == "superadmin":
            return True
        if self._user_obj and self._user_obj.email in SUPERADMIN_EMAILS:
            return True
        return False

    @property
    def is_admin(self) -> bool:
        return self.is_superadmin or self.role in ("admin", "superadmin")

    @property
    def is_analyst(self) -> bool:
        return self.is_admin or self.role == "analyst"

    @property
    def is_viewer(self) -> bool:
        return self.role == "viewer"

    @property
    def org(self):
        if self._org_obj:
            return self._org_obj
        try:
            u_id = uuid.UUID(self.org_id)
        except Exception:
            u_id = self.org_id
        return SimpleNamespace(id=u_id, name="Active Organization", slug="active-org")

    @property
    def user(self):
        if self._user_obj:
            return self._user_obj
        try:
            u_id = uuid.UUID(self.user_id)
        except Exception:
            u_id = self.user_id
        return SimpleNamespace(id=u_id, email="analyst@signalthread.io", name="Security Analyst")

    def has_any_role(self, *roles: str) -> bool:
        if self.is_superadmin:
            return True
        return self.role in roles


TenantContext = Tenant


async def get_tenant(claims: dict = Depends(get_token_claims), db: AsyncSession = Depends(get_db)) -> Tenant:
    org_id = claims.get("org_id")
    if not org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active organization selected")

    try:
        uuid.UUID(org_id)
    except ValueError:
        raise _unauthorized()

    user = await db.get(User, claims.get("sub"))
    if not user or not user.is_active:
        raise _unauthorized()

    membership = await db.scalar(
        select(OrganizationMember).where(OrganizationMember.org_id == org_id, OrganizationMember.user_id == user.id)
    )
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this organization")

    org = await db.get(Organization, org_id)

    # Attach superadmin role if user is in superadmin list
    role = membership.role
    if user.email in SUPERADMIN_EMAILS and role == "admin":
        role = "superadmin"

    return Tenant(org_id=str(org_id), role=role, user_id=str(user.id), user=user, org=org)


def require_roles(*roles: str):
    """RBAC guard: decorator-style dependency factory."""

    async def checker(tenant: Tenant = Depends(get_tenant)) -> Tenant:
        if not tenant.has_any_role(*roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return tenant

    return checker


def require_superadmin():
    """Strict Superadmin-only guard for global multi-tenant control plane."""

    async def checker(tenant: Tenant = Depends(get_tenant)) -> Tenant:
        if not tenant.is_superadmin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin authorization required")
        return tenant

    return checker
