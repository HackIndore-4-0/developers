import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------- Auth ----------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RoleEnum(str):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ---------- User ----------
class UserBase(BaseModel):
    email: EmailStr
    name: str | None = None


class UserOut(UserBase):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    is_active: bool
    created_at: datetime


class MeOut(BaseModel):
    user: UserOut
    active_org: "OrgSummary | None" = None
    organizations: list["OrgSummary"] = []
    roles: list[str] = []


# ---------- Organization ----------
class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str = Field(min_length=2, max_length=255, pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str | None = None


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = None
    logo_url: str | None = None


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    logo_url: str | None = None
    created_at: datetime


class OrgSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    slug: str


# ---------- Members ----------
class MemberInvite(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class MemberUpdate(BaseModel):
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class MemberOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    org_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    joined_at: datetime
    email: str | None = None
    name: str | None = None


class RoleOut(BaseModel):
    name: str
    description: str


MeOut.model_rebuild()