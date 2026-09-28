import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


# ---------- Assets ----------


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "hostname"),
        Index("ix_assets_org_type", "org_id", "type"),
        Index("ix_assets_org_status", "org_id", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(512), nullable=False)
    domain = Column(String(255), index=True)
    type = Column(String(50), nullable=False, default="host")  # domain|subdomain|ip|api|host
    ip = Column(String(45))
    url = Column(String(1024))
    criticality = Column(String(20), nullable=False, default="low")  # low|medium|high|critical
    environment = Column(String(20), default="production")  # production|staging|dev
    status = Column(String(20), nullable=False, default="active")  # active|inactive|unknown
    owner = Column(String(255))
    tech_stack = Column(JSON, default=list)
    title = Column(String(255))
    status_code = Column(Integer)
    content_length = Column(Integer)
    screenshot = Column(String(1024))
    tags = Column(JSON, default=list)
    description = Column(Text)
    metadata_ = Column("metadata", JSON, default=dict)
    discovered_by = Column(String(100), default="manual")
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AssetHistory(Base):
    __tablename__ = "asset_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    field = Column(String(100), nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    changed_by = Column(String(100))
    changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AssetTech(Base):
    __tablename__ = "asset_tech"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    version = Column(String(100))
    confidence = Column(Float, default=1.0)
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AssetPort(Base):
    __tablename__ = "asset_ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")
    service = Column(String(100))
    state = Column(String(20), default="open")
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AssetCert(Base):
    __tablename__ = "asset_certs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    subject_cn = Column(String(255))
    issuer_cn = Column(String(255))
    san = Column(JSON, default=list)
    expires_at = Column(DateTime(timezone=True))
    fingerprint = Column(String(255))
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Subdomains ----------


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("org_id", "domain"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(512), nullable=False, index=True)
    parent_domain = Column(String(255), index=True)
    ips = Column(JSON, default=list)
    technologies = Column(JSON, default=list)
    status = Column(String(20), default="active")  # active|inactive|wildcard
    status_code = Column(Integer)
    title = Column(String(255))
    discoveries = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SubdomainHistory(Base):
    __tablename__ = "subdomain_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, index=True)
    field = Column(String(100), nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Network Scans ----------


class NetworkScan(Base):
    __tablename__ = "network_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(512), nullable=False)
    type = Column(String(50), default="Port Scan")  # Port Scan|Service Detect|OS Detection|Network Map
    status = Column(String(20), default="pending")  # pending|running|completed|failed|cancelled
    hosts_count = Column(Integer, default=0)
    ports_count = Column(Integer, default=0)
    services_count = Column(Integer, default=0)
    duration = Column(String(50))
    result = Column(JSON, default=dict)
    error = Column(Text)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class NetworkScanHost(Base):
    __tablename__ = "network_scan_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("network_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(45), nullable=False)
    hostname = Column(String(512))
    status = Column(String(20), default="up")
    os_match = Column(String(255))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class NetworkScanPort(Base):
    __tablename__ = "network_scan_ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("network_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service = Column(String(100))
    state = Column(String(20), default="open")


class NetworkScanService(Base):
    __tablename__ = "network_scan_services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("network_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    name = Column(String(100), nullable=False)
    version = Column(String(100))
    banner = Column(Text)


# ---------- Vulnerabilities ----------


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_org_severity", "org_id", "severity"),
        Index("ix_vuln_org_status", "org_id", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    cve = Column(String(50), index=True)
    template_id = Column(String(512))
    description = Column(Text)
    severity = Column(String(20), nullable=False, default="info")  # critical|high|medium|low|info
    cvss = Column(Float)
    cwe = Column(String(20))
    remediation = Column(Text)
    status = Column(String(20), nullable=False, default="open")  # open|fixed|false_positive|accepted|in_progress
    evidence = Column(JSON, default=dict)
    source = Column(String(50), default="nuclei")  # nuclei|nmap|acunetix|manual
    assignee = Column(String(255))
    matched_at = Column(String(500))
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class VulnerabilityScan(Base):
    __tablename__ = "vulnerability_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    target = Column(String(512))
    job_id = Column(UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="SET NULL"))
    engine = Column(String(50), default="nuclei")  # nuclei|acunetix|nessus|openvas|burp
    tool = Column(String(50), default="nuclei")
    status = Column(String(20), default="queued")  # queued|running|completed|failed|cancelled
    findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    duration = Column(String(50))
    schedule = Column(String(50))  # Daily|Weekly|Monthly
    started_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Exposures (leak intelligence) ----------


class Exposure(Base):
    __tablename__ = "exposures"
    __table_args__ = (Index("ix_exposure_org_type", "org_id", "type"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(30), nullable=False)  # credential|email|password|api_key|token|source_code|stealer_log|breach
    affected_identity = Column(String(512), index=True)
    domain = Column(String(255))
    source = Column(String(255))
    severity = Column(String(20), default="medium")
    status = Column(String(20), default="open")  # open|acknowledged|resolved
    mask = Column(String(255))
    secret_type = Column(String(50))
    evidence = Column(JSON, default=dict)
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ExposureEvent(Base):
    __tablename__ = "exposure_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exposure_id = Column(UUID(as_uuid=True), ForeignKey("exposures.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(50), default="seen")  # seen|related_asset|alert|resolved
    description = Column(Text)
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Discovery ----------


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(512), nullable=False)
    tool = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    source = Column(String(20), nullable=False, default="tool")
    progress = Column(Integer, default=0)
    findings = Column(Integer, default=0)
    result = Column(JSON, default=dict)
    error = Column(Text)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    job_id = Column(UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    host = Column(String(512), nullable=False)
    ip = Column(String(45))
    type = Column(String(50), default="host")
    data = Column(JSON, default=dict)
    found_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Repositories & Secrets ----------


class CodeRepository(Base):
    __tablename__ = "code_repositories"
    __table_args__ = (UniqueConstraint("org_id", "url"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    provider = Column(String(50), default="github")  # github|gitlab|bitbucket|azure
    url = Column(String(1024), nullable=False)
    branch = Column(String(100), default="main")
    status = Column(String(20), default="connected")  # connected|scanning|failed|disabled
    owner = Column(String(255))
    findings_count = Column(Integer, default=0)
    secrets_count = Column(Integer, default=0)
    last_scan = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class SecretFinding(Base):
    __tablename__ = "secret_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_id = Column(UUID(as_uuid=True), ForeignKey("code_repositories.id", ondelete="CASCADE"), nullable=True, index=True)
    secret_type = Column(String(100), nullable=False)  # api_key|private_key|password|jwt|aws_secret|token
    description = Column(String(512))
    file_path = Column(String(1024))
    line_number = Column(Integer)
    commit_hash = Column(String(100))
    author = Column(String(255))
    raw_preview = Column(String(255))
    status = Column(String(20), default="open")  # open|revoked|resolved|false_positive
    severity = Column(String(20), default="high")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Events & Detections ----------


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    source = Column(String(100), nullable=False)  # auth|network|edr|cloud|wapi
    severity = Column(String(20), default="info")  # critical|high|medium|low|info
    actor = Column(String(255))
    target = Column(String(512))
    action = Column(String(100))
    ip_address = Column(String(45))
    payload = Column(JSON, default=dict)
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    rule_id_code = Column(String(50))  # DET-042
    category = Column(String(100), default="Authentication")
    severity = Column(String(20), default="high")
    status = Column(String(20), default="active")  # active|testing|disabled
    logic = Column(Text, nullable=False)
    description = Column(Text)
    matches_count = Column(Integer, default=0)
    last_triggered = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ---------- Alerts ----------


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_org_severity", "org_id", "severity"),
        Index("ix_alerts_org_status", "org_id", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_code = Column(String(50))  # ALT-1093
    title = Column(String(512), nullable=False)
    category = Column(String(100), default="Threat")
    severity = Column(String(20), default="high")
    status = Column(String(20), default="open")  # open|acknowledged|investigating|contained|dismissed|escalated
    source = Column(String(100), default="Detection Engine")
    assignee = Column(String(255))
    description = Column(Text)
    evidence = Column(JSON, default=dict)
    events_count = Column(Integer, default=1)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL"))
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=True)
    description = Column(String(512))
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Incidents ----------


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_org_status", "org_id", "status"),
        Index("ix_incidents_org_severity", "org_id", "severity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_code = Column(String(50))  # INC-0042
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="critical")  # critical|high|medium|low
    status = Column(String(20), default="open")  # open|investigating|contained|closed
    stage = Column(Integer, default=1)  # 1: Detect, 2: Scope, 3: Contain, 4: Eradicate, 5: Recover
    assignee = Column(String(255))
    ttp = Column(String(100))  # Exfiltration|Impact|Privilege Escalation|Credential Access
    iocs_count = Column(Integer, default=0)
    assets_count = Column(Integer, default=0)
    events_count = Column(Integer, default=0)
    attack_chain = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100))
    description = Column(Text, nullable=False)
    user_name = Column(String(100))
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class IncidentAsset(Base):
    __tablename__ = "incident_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    hostname = Column(String(512), nullable=False)
    impact = Column(String(50), default="compromised")


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False)  # ip|domain|hash|url|email
    value = Column(String(512), nullable=False)
    description = Column(String(512))


class IncidentTimeline(Base):
    __tablename__ = "incident_timelines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    actor = Column(String(100))
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Response Actions ----------


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    action_code = Column(String(50))  # RA-0045
    type = Column(String(100), nullable=False)  # Block IP|Revoke Session|Revoke Token|Disable User|Isolate Endpoint
    target = Column(String(512), nullable=False)
    status = Column(String(20), default="pending")  # pending|approved|rejected|executing|completed|failed
    requested_by = Column(String(255))
    description = Column(Text)
    result = Column(String(512))
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"))
    requested_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    executed_at = Column(DateTime(timezone=True))


# ---------- Threat Intelligence ----------


class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # ip|domain|hash|url
    value = Column(String(512), nullable=False, index=True)
    reputation = Column(String(20), default="suspicious")  # malicious|suspicious|benign|unknown
    source = Column(String(100), default="AlienVault OTX")
    tags = Column(JSON, default=list)
    asn = Column(String(50))
    country = Column(String(100))
    owner = Column(String(255))
    malware = Column(JSON, default=list)
    campaigns = Column(JSON, default=list)
    ttps = Column(JSON, default=list)
    description = Column(Text)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    aliases = Column(JSON, default=list)
    origin = Column(String(100))
    targeted_industries = Column(JSON, default=list)
    targeted_countries = Column(JSON, default=list)
    malware_used = Column(JSON, default=list)
    ttps = Column(JSON, default=list)
    description = Column(Text)
    first_seen = Column(String(50))
    active = Column(Boolean, default=True)


class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    actor_name = Column(String(255))
    objective = Column(String(255))
    malware = Column(JSON, default=list)
    iocs_count = Column(Integer, default=0)
    status = Column(String(20), default="active")
    first_seen = Column(String(50))


class ThreatMalware(Base):
    __tablename__ = "threat_malware"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    type = Column(String(100), default="Ransomware")  # Ransomware|Trojan|Stealer|Backdoor|C2
    families = Column(JSON, default=list)
    platforms = Column(JSON, default=list)
    description = Column(Text)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(String(50), primary_key=True)  # T1071.001
    name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False)
    description = Column(Text)
    platforms = Column(JSON, default=list)


# ---------- Escalation & Notifications ----------


class EscalationPolicy(Base):
    __tablename__ = "escalation_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    severity = Column(String(20), default="critical")
    enabled = Column(Boolean, default=True)
    steps = Column(JSON, default=list)
    incidents_count = Column(Integer, default=0)
    last_triggered = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class NotificationRecord(Base):
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(50), default="email")  # email|slack|teams|twilio|webhook
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    recipient = Column(String(255))
    status = Column(String(20), default="sent")  # sent|failed|pending
    error = Column(Text)
    sent_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ---------- Integrations ----------


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    __table_args__ = (UniqueConstraint("org_id", "provider"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # acunetix|hibp|github|slack|teams|email|twilio
    enabled = Column(Boolean, default=False)
    status = Column(String(20), default="connected")  # connected|disconnected|error
    config = Column(JSON, default=dict)
    last_sync = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ---------- Reports & Audit ----------


class ReportRecord(Base):
    __tablename__ = "report_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    type = Column(String(50), default="executive")  # executive|security|incident|compliance
    format = Column(String(10), default="pdf")  # pdf|csv|json
    status = Column(String(20), default="generated")  # queued|generating|generated|failed
    file_size = Column(String(50))
    parameters = Column(JSON, default=dict)
    download_url = Column(String(1024))
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    actor = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(512), nullable=False)
    detail = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ---------- AI Investigations & Conversations ----------


class AIInvestigation(Base):
    __tablename__ = "ai_investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    inv_code = Column(String(50))  # INV-0012
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"))
    query = Column(Text, nullable=False)
    status = Column(String(20), default="completed")  # pending|running|completed|failed
    findings_count = Column(Integer, default=0)
    confidence = Column(Integer, default=90)
    model = Column(String(100), default="Claude 3.5 Sonnet")
    analysis = Column(JSON, default=dict)
    recommendations = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True))


class AIConversation(Base):
    __tablename__ = "ai_conversations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), default="New Investigation")
    messages = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
