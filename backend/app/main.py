from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import (
    ai,
    alerts,
    assets,
    audit,
    auth,
    changes,
    dashboard,
    discovery,
    escalation,
    events,
    exposures,
    graph,
    incidents,
    integrations,
    library,
    monitoring,
    network,
    organizations,
    reports,
    repositories,
    response,
    risk,
    scan_profiles,
    subdomains,
    superadmin,
    threat_intel,
    vulnerabilities,
    ws,
)

tags_metadata = [
    {"name": "Authentication", "description": "User login, refresh token, session revocation, and identity bootstrap."},
    {"name": "Organizations", "description": "Multi-tenant workspaces, membership roles, and workspace settings."},
    {"name": "Assets", "description": "Continuous asset discovery, probe context, port/tech fingerprinting, and screenshots."},
    {"name": "Subdomains", "description": "Subdomain discovery, enumeration, wildcard monitoring, and change history."},
    {"name": "Network Scans", "description": "Port scanning, service detection, OS fingerprinting, and scan host management."},
    {"name": "Vulnerabilities", "description": "CVE tracking, vulnerability triage, lifecycle status, and verification."},
    {"name": "Vulnerability Scans", "description": "Scheduled and on-demand engine-based vulnerability assessments."},
    {"name": "Exposures", "description": "Credential leak intelligence, dark web stealer log analysis, and breach correlation."},
    {"name": "Code Repositories & Secrets", "description": "Source code repository scanning and secret finding remediation."},
    {"name": "Events & Detections", "description": "Real-time security telemetry ingestion, detection rules, and rule testing."},
    {"name": "Alerts", "description": "Alert triage queue, escalation, event grouping, and analyst assignment."},
    {"name": "Incidents & Attack Graphs", "description": "Full-cycle incident response, evidence, timelines, and attack graph generation."},
    {"name": "Response Actions", "description": "Automated containment actions: IP blocking, session revocation, and endpoint isolation."},
    {"name": "AI & Copilot", "description": "AI-driven investigations, automated threat analysis, and copilot conversational assist."},
    {"name": "Security Graph", "description": "Neo4j graph intelligence, attack path discovery, and blast radius calculation."},
    {"name": "Threat Intelligence", "description": "IOC enrichment (IP/domain/hash/url), threat actors, campaigns, malware, and MITRE ATT&CK."},
    {"name": "Risk & Posture", "description": "Quantitative risk scoring, driver breakdown, and posture recalculation."},
    {"name": "Escalation Policies & Notifications", "description": "Automated escalation step policies, notification dispatch, and test alerts."},
    {"name": "Monitoring & Health", "description": "Platform health checks, service latencies, worker queue status, and asset monitoring."},
    {"name": "Integrations", "description": "Third-party connector configurations: Acunetix, HIBP, GitHub, Slack, Teams, Email, Twilio."},
    {"name": "Dashboard Aggregates", "description": "Executive dashboard posture summaries, trend line datasets, and top issue metrics."},
    {"name": "Reports", "description": "Report generation, executive summaries, security audit exports, and compliance bundles."},
    {"name": "Audit Logs", "description": "WORM-style audit log trail with actor tracking, actions, targets, and CSV export."},
    {"name": "WebSockets", "description": "Real-time bidirectional streams for events, alerts, incidents, and investigation updates."},
]

app = FastAPI(
    title="SignalThread CTEM & SOC API",
    description="AI-native continuous exposure management, dark web intelligence, real-time SOC detection & response platform API.",
    version="1.0.0",
    openapi_tags=tags_metadata,
    debug=settings.debug,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- REST API v1 Routes ----------
app.include_router(auth.router, prefix=settings.api_v1_prefix)
app.include_router(organizations.router, prefix=settings.api_v1_prefix)
app.include_router(assets.router, prefix=settings.api_v1_prefix)
app.include_router(assets.factory_router, prefix=settings.api_v1_prefix)
app.include_router(subdomains.router, prefix=settings.api_v1_prefix)
app.include_router(network.router, prefix=settings.api_v1_prefix)
app.include_router(vulnerabilities.router, prefix=settings.api_v1_prefix)
app.include_router(vulnerabilities.factory_router, prefix=settings.api_v1_prefix)
app.include_router(vulnerabilities.scans_router, prefix=settings.api_v1_prefix)
app.include_router(discovery.router, prefix=settings.api_v1_prefix)
app.include_router(exposures.router, prefix=settings.api_v1_prefix)
app.include_router(exposures.factory_router, prefix=settings.api_v1_prefix)
app.include_router(repositories.router, prefix=settings.api_v1_prefix)
app.include_router(events.router, prefix=settings.api_v1_prefix)
app.include_router(alerts.router, prefix=settings.api_v1_prefix)
app.include_router(incidents.router, prefix=settings.api_v1_prefix)
app.include_router(response.router, prefix=settings.api_v1_prefix)
app.include_router(ai.router, prefix=settings.api_v1_prefix)
app.include_router(graph.router, prefix=settings.api_v1_prefix)
app.include_router(threat_intel.router, prefix=settings.api_v1_prefix)
app.include_router(risk.router, prefix=settings.api_v1_prefix)
app.include_router(escalation.router, prefix=settings.api_v1_prefix)
app.include_router(monitoring.router, prefix=settings.api_v1_prefix)
app.include_router(integrations.router, prefix=settings.api_v1_prefix)
app.include_router(dashboard.router, prefix=settings.api_v1_prefix)
app.include_router(reports.router, prefix=settings.api_v1_prefix)
app.include_router(audit.router, prefix=settings.api_v1_prefix)
app.include_router(library.router, prefix=settings.api_v1_prefix)
app.include_router(scan_profiles.router, prefix=settings.api_v1_prefix)
app.include_router(changes.router, prefix=settings.api_v1_prefix)
app.include_router(superadmin.router, prefix=settings.api_v1_prefix)
app.include_router(ws.router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "SignalThread API", "version": "1.0.0"}


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "SignalThread API",
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
        "health": "/health",
    }
