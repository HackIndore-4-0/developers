import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------- Subdomains ----------


class SubdomainCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=512)
    parent_domain: str | None = None
    ips: list[str] = []
    technologies: list[str] = []
    status: str = "active"


class SubdomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    domain: str
    parent_domain: str | None = None
    ips: list[str] = []
    technologies: list[str] = []
    status: str
    status_code: int | None = None
    title: str | None = None
    discoveries: int = 0
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class SubdomainHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    subdomain_id: uuid.UUID
    field: str
    old_value: str | None = None
    new_value: str | None = None
    changed_at: datetime


# ---------- Network Scans ----------


class NetworkScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    type: str = "Port Scan"


class NetworkScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    target: str
    type: str
    status: str
    hosts_count: int = 0
    ports_count: int = 0
    services_count: int = 0
    duration: str | None = None
    result: dict[str, Any] = {}
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class NetworkScanHostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    ip: str
    hostname: str | None = None
    status: str
    os_match: str | None = None
    created_at: datetime


class NetworkScanPortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    ip: str
    port: int
    protocol: str
    service: str | None = None
    state: str


class NetworkScanServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    ip: str
    port: int
    name: str
    version: str | None = None
    banner: str | None = None


# ---------- Vulnerabilities Action Schemas ----------


class VulnAssignReq(BaseModel):
    assignee: str


class VulnActionResp(BaseModel):
    status: str = "ok"
    vulnerability_id: uuid.UUID
    action: str
    detail: str | None = None


# ---------- Code Repositories & Secrets ----------


class CodeRepoCreate(BaseModel):
    name: str
    provider: str = "github"
    url: str
    branch: str = "main"
    owner: str | None = None


class CodeRepoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    provider: str
    url: str
    branch: str
    status: str
    owner: str | None = None
    findings_count: int = 0
    secrets_count: int = 0
    last_scan: datetime | None = None
    created_at: datetime


class SecretFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    repo_id: uuid.UUID | None = None
    secret_type: str
    description: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    commit_hash: str | None = None
    author: str | None = None
    raw_preview: str | None = None
    status: str
    severity: str
    created_at: datetime


# ---------- Security Events & Detection Rules ----------


class SecurityEventCreate(BaseModel):
    event_type: str
    source: str
    severity: str = "info"
    actor: str | None = None
    target: str | None = None
    action: str | None = None
    ip_address: str | None = None
    payload: dict[str, Any] = {}


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    event_type: str
    source: str
    severity: str
    actor: str | None = None
    target: str | None = None
    action: str | None = None
    ip_address: str | None = None
    payload: dict[str, Any] = {}
    occurred_at: datetime
    created_at: datetime


class DetectionRuleCreate(BaseModel):
    name: str
    rule_id_code: str | None = None
    category: str = "Authentication"
    severity: str = "high"
    status: str = "active"
    logic: str
    description: str | None = None


class DetectionRuleUpdate(BaseModel):
    name: str | None = None
    category: str | None = None
    severity: str | None = None
    status: str | None = None
    logic: str | None = None
    description: str | None = None


class DetectionRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    rule_id_code: str | None = None
    category: str
    severity: str
    status: str
    logic: str
    description: str | None = None
    matches_count: int = 0
    last_triggered: datetime | None = None
    created_at: datetime


# ---------- Alerts ----------


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    alert_code: str | None = None
    title: str
    category: str
    severity: str
    status: str
    source: str
    assignee: str | None = None
    description: str | None = None
    evidence: dict[str, Any] = {}
    events_count: int = 1
    rule_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


class AlertAssignReq(BaseModel):
    assignee: str


# ---------- Incidents ----------


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: str = "critical"
    ttp: str | None = None
    assignee: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    stage: int | None = None
    assignee: str | None = None
    ttp: str | None = None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    incident_code: str | None = None
    title: str
    description: str | None = None
    severity: str
    status: str
    stage: int
    assignee: str | None = None
    ttp: str | None = None
    iocs_count: int = 0
    assets_count: int = 0
    events_count: int = 0
    attack_chain: list[Any] = []
    created_at: datetime
    updated_at: datetime


class IncidentTimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    description: str | None = None
    actor: str | None = None
    occurred_at: datetime


class IncidentEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    event_type: str | None = None
    description: str
    user_name: str | None = None
    occurred_at: datetime


class IncidentAssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    asset_id: uuid.UUID | None = None
    hostname: str
    impact: str


class IncidentIOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    ioc_type: str
    value: str
    description: str | None = None


# ---------- Response Actions ----------


class ResponseActionCreate(BaseModel):
    type: str
    target: str
    description: str | None = None
    incident_id: uuid.UUID | None = None


class ResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    action_code: str | None = None
    type: str
    target: str
    status: str
    requested_by: str | None = None
    description: str | None = None
    result: str | None = None
    incident_id: uuid.UUID | None = None
    requested_at: datetime
    executed_at: datetime | None = None


class BlockIpReq(BaseModel):
    ip: str
    reason: str = "Malicious activity"


class RevokeSessionReq(BaseModel):
    session_id: str
    reason: str = "Compromised credential"


class RevokeTokenReq(BaseModel):
    token: str
    reason: str = "Token leaked"


class DisableUserReq(BaseModel):
    user_email: str
    reason: str = "Account compromised"


class IsolateEndpointReq(BaseModel):
    hostname: str
    reason: str = "Active ransomware detection"


# ---------- Threat Intelligence ----------


class ThreatIOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    type: str
    value: str
    reputation: str
    source: str
    tags: list[str] = []
    asn: str | None = None
    country: str | None = None
    owner: str | None = None
    malware: list[str] = []
    campaigns: list[str] = []
    ttps: list[str] = []
    description: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime


class ThreatActorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    aliases: list[str] = []
    origin: str | None = None
    targeted_industries: list[str] = []
    targeted_countries: list[str] = []
    malware_used: list[str] = []
    ttps: list[str] = []
    description: str | None = None
    first_seen: str | None = None
    active: bool = True


class ThreatCampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    actor_name: str | None = None
    objective: str | None = None
    malware: list[str] = []
    iocs_count: int = 0
    status: str = "active"
    first_seen: str | None = None


class ThreatMalwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: str
    families: list[str] = []
    platforms: list[str] = []
    description: str | None = None


class MitreTechniqueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    tactic: str
    description: str | None = None
    platforms: list[str] = []


# ---------- Escalation Policies ----------


class EscalationPolicyCreate(BaseModel):
    name: str
    severity: str = "critical"
    enabled: bool = True
    steps: list[dict[str, Any]] = []


class EscalationPolicyUpdate(BaseModel):
    name: str | None = None
    severity: str | None = None
    enabled: bool | None = None
    steps: list[dict[str, Any]] | None = None


class EscalationPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    severity: str
    enabled: bool
    steps: list[dict[str, Any]] = []
    incidents_count: int = 0
    last_triggered: datetime | None = None
    created_at: datetime


# ---------- Notifications ----------


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    channel: str
    title: str
    message: str
    recipient: str | None = None
    status: str
    sent_at: datetime


class NotificationTestReq(BaseModel):
    channel: str = "email"
    recipient: str | None = None
    message: str = "Test notification from SignalThread"


# ---------- Integrations ----------


class IntegrationCreate(BaseModel):
    provider: str
    enabled: bool = True
    config: dict[str, Any] = {}


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    status: str | None = None
    config: dict[str, Any] | None = None


class IntegrationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    provider: str
    enabled: bool
    status: str
    config: dict[str, Any] = {}
    last_sync: datetime | None = None
    created_at: datetime


class ProviderConnectReq(BaseModel):
    api_key: str | None = None
    api_url: str | None = None
    webhook_url: str | None = None
    token: str | None = None
    config: dict[str, Any] = {}


# ---------- Reports ----------


class ReportCreate(BaseModel):
    title: str
    type: str = "executive"
    format: str = "pdf"
    parameters: dict[str, Any] = {}


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    title: str
    type: str
    format: str
    status: str
    file_size: str | None = None
    download_url: str | None = None
    created_by: str | None = None
    created_at: datetime


# ---------- Audit Logs ----------


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    actor: str
    action: str
    target: str
    detail: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    occurred_at: datetime


# ---------- AI Investigations & Chat ----------


class AIInvestigateReq(BaseModel):
    query: str
    incident_id: uuid.UUID | None = None
    model: str = "Claude 3.5 Sonnet"


class AIInvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    inv_code: str | None = None
    incident_id: uuid.UUID | None = None
    query: str
    status: str
    findings_count: int = 0
    confidence: int = 90
    model: str
    analysis: dict[str, Any] = {}
    recommendations: list[Any] = []
    created_at: datetime
    completed_at: datetime | None = None


class AIChatReq(BaseModel):
    prompt: str
    conversation_id: uuid.UUID | None = None


class AIConversationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    title: str
    messages: list[dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime
