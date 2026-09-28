import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# ---------- Asset ----------


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=512)
    domain: str | None = None
    type: str = "host"
    ip: str | None = None
    url: str | None = None
    criticality: str = "low"
    environment: str = "production"
    status: str = "active"
    owner: str | None = None
    tech_stack: list[str] = []
    tags: list[str] = []
    description: str | None = None
    discovered_by: str = "manual"


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, max_length=512)
    domain: str | None = None
    type: str | None = None
    ip: str | None = None
    url: str | None = None
    criticality: str | None = None
    environment: str | None = None
    status: str | None = None
    owner: str | None = None
    tech_stack: list[str] | None = None
    tags: list[str] | None = None
    description: str | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    hostname: str
    domain: str | None = None
    type: str
    ip: str | None = None
    url: str | None = None
    criticality: str
    environment: str
    status: str
    owner: str | None = None
    tech_stack: list[str] = []
    title: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    tags: list[str] = []
    description: str | None = None
    discovered_by: str = "manual"
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class AssetListOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    hostname: str
    type: str
    ip: str | None = None
    url: str | None = None
    title: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    criticality: str
    environment: str
    status: str
    owner: str | None = None
    tech_stack: list[str] = []
    tags: list[str] = []
    screenshot: str | None = None
    created_at: datetime


# ---------- Asset History ----------


class AssetHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    field: str
    old_value: str | None = None
    new_value: str | None = None
    changed_by: str | None = None
    changed_at: datetime


# ---------- Asset Tech ----------


class AssetTechOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    version: str | None = None
    confidence: float = 1.0
    first_seen: datetime


# ---------- Asset Ports ----------


class AssetPortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    port: int
    protocol: str
    service: str | None = None
    state: str = "open"
    last_seen: datetime


# ---------- Asset Certs ----------


class AssetCertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    subject_cn: str | None = None
    issuer_cn: str | None = None
    san: list[str] = []
    expires_at: datetime | None = None
    fingerprint: str | None = None
    first_seen: datetime


# ---------- Discovery ----------


class DiscoveryRunRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512, description="domain, IP, or CIDR")
    tool: str = Field(description="subfinder|nmap|httpx|nuclei|masscan|assetfinder")
    source: str = "tool"


class DiscoveryJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    org_id: uuid.UUID
    target: str
    tool: str
    status: str
    source: str
    progress: int = 0
    findings: int = 0
    result: dict = {}
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class DiscoveredHostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    host: str
    ip: str | None = None
    type: str = "host"
    data: dict = {}
    found_at: datetime