import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.security import AssetOut, DiscoveryJobOut


# ---------- Vulnerability ----------
class VulnerabilityCreate(BaseModel):
    asset_id: uuid.UUID
    title: str = Field(min_length=1, max_length=512)
    cve: str | None = None
    template_id: str | None = None
    description: str | None = None
    severity: str = "info"
    cvss: float | None = None
    cwe: str | None = None
    remediation: str | None = None
    status: str = "open"
    source: str = "manual"
    matched_at: str | None = None


class VulnerabilityUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    cvss: float | None = None
    remediation: str | None = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    cve: str | None = None
    template_id: str | None = None
    description: str | None = None
    severity: str
    cvss: float | None = None
    cwe: str | None = None
    remediation: str | None = None
    status: str
    source: str
    matched_at: str | None = None
    first_seen: datetime
    created_at: datetime


class VulnerabilityListOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    cve: str | None = None
    severity: str
    cvss: float | None = None
    status: str
    source: str
    first_seen: datetime


# ---------- Scans ----------
class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    tool: str
    status: str
    findings: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


# ---------- Exposure ----------
class ExposureCreate(BaseModel):
    type: str
    affected_identity: str
    domain: str | None = None
    source: str
    severity: str = "medium"
    status: str = "open"
    mask: str | None = None
    secret_type: str | None = None


class ExposureUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None


class ExposureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    org_id: uuid.UUID
    type: str
    affected_identity: str
    domain: str | None = None
    source: str
    severity: str
    status: str
    mask: str | None = None
    secret_type: str | None = None
    first_seen: datetime
    created_at: datetime


class ExposureListOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    type: str
    affected_identity: str
    domain: str | None = None
    source: str
    severity: str
    status: str
    mask: str | None = None
    first_seen: datetime


class ExposureEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    kind: str
    description: str | None = None
    occurred_at: datetime


class AssetWithVulns(AssetOut):
    vulnerabilities: list[VulnerabilityListOut] = []


class AssetWithExposures(AssetOut):
    exposures: list[ExposureListOut] = []