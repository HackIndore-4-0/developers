import asyncio
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models import (
    AIConversation,
    AIInvestigation,
    Alert,
    AlertEvent,
    Asset,
    AssetCert,
    AssetHistory,
    AssetPort,
    AssetTech,
    AuditLog,
    CodeRepository,
    DetectionRule,
    DiscoveredHost,
    DiscoveryJob,
    EscalationPolicy,
    Exposure,
    ExposureEvent,
    Incident,
    IncidentAsset,
    IncidentEvent,
    IncidentIOC,
    IncidentTimeline,
    IntegrationConfig,
    MitreTechnique,
    NetworkScan,
    NetworkScanHost,
    NetworkScanPort,
    NetworkScanService,
    NotificationRecord,
    Organization,
    OrganizationMember,
    ReportRecord,
    ResponseAction,
    SecretFinding,
    SecurityEvent,
    Subdomain,
    SubdomainHistory,
    ThreatActor,
    ThreatCampaign,
    ThreatIOC,
    ThreatMalware,
    User,
    Vulnerability,
    VulnerabilityScan,
)


def utcnow():
    return datetime.now(timezone.utc)


async def seed():
    async with AsyncSessionLocal() as db:
        print("[*] Seeding SignalThread Enterprise CTEM & SOC Database...")

        # 1. Admin User
        user = await db.scalar(select(User).where(User.email == "admin@aurora.ai"))
        if not user:
            user = User(
                email="admin@aurora.ai",
                password_hash=hash_password("Admin@123"),
                name="Anaya Shah",
                is_active=True,
            )
            db.add(user)
            await db.flush()

        # 2. Organization
        org = await db.scalar(select(Organization).where(Organization.slug == "aurora-bank"))
        if not org:
            org = Organization(
                name="Aurora Bank",
                slug="aurora-bank",
                description="Aurora Financial & Commercial Banking Enterprise",
            )
            db.add(org)
            await db.flush()

        # 3. Membership
        member = await db.scalar(
            select(OrganizationMember).where(OrganizationMember.org_id == org.id, OrganizationMember.user_id == user.id)
        )
        if not member:
            member = OrganizationMember(
                org_id=org.id,
                user_id=user.id,
                role="admin",
            )
            db.add(member)

        # 4. MITRE Techniques
        mitre_data = [
            ("T1190", "Exploit Public-Facing Application", "Initial Access", ["Linux", "Windows"]),
            ("T1078", "Valid Accounts", "Defense Evasion", ["Cloud", "Identity"]),
            ("T1059.001", "PowerShell Execution", "Execution", ["Windows"]),
            ("T1071.001", "Web Protocols C2", "Command and Control", ["Network"]),
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", ["Network"]),
            ("T1562.004", "Disable or Modify System Firewall", "Defense Evasion", ["Linux", "Windows"]),
        ]
        for tid, name, tactic, plats in mitre_data:
            existing = await db.scalar(select(MitreTechnique).where(MitreTechnique.id == tid))
            if not existing:
                db.add(MitreTechnique(id=tid, name=name, tactic=tactic, description=f"MITRE ATT&CK technique {name}", platforms=plats))

        # 5. Threat Actors & Malware
        actors = [
            ("APT28", ["Fancy Bear", "Sofacy"], "Russia", ["Finance", "Defense"], ["Conti", "Lockbit"], "Nation-state espionage group"),
            ("Scattered Spider", ["UNC3944"], "Global", ["Technology", "Fintech"], ["AgentTesla"], "Social engineering and SIM-swapping threat group"),
        ]
        for name, aliases, origin, inds, mal, desc in actors:
            existing = await db.scalar(select(ThreatActor).where(ThreatActor.name == name))
            if not existing:
                db.add(ThreatActor(name=name, aliases=aliases, origin=origin, targeted_industries=inds, malware_used=mal, description=desc))

        malware_items = [
            ("Lockbit 3.0", "Ransomware", ["Windows", "Linux"], "Double extortion ransomware operator."),
            ("Conti", "Ransomware", ["Windows"], "Modular enterprise ransomware."),
            ("AgentTesla", "Stealer", ["Windows"], "Advanced infostealer targeting browser and VPN credentials."),
        ]
        for name, mtype, plats, desc in malware_items:
            existing = await db.scalar(select(ThreatMalware).where(ThreatMalware.name == name))
            if not existing:
                db.add(ThreatMalware(name=name, type=mtype, platforms=plats, description=desc))

        # 6. Detection Rules
        rules = [
            ("DET-042", "Brute force login attempts on VPN", "Authentication", "high", "Failed logins > 5 from same IP in 5 min"),
            ("DET-041", "Unauthorized API key usage from Tor", "Secrets", "critical", "API key used from known Tor exit node"),
            ("DET-040", "Port scan detection threshold", "Reconnaissance", "medium", "> 100 ports probed from single source"),
            ("DET-039", "Suspicious data exfiltration over HTTP", "Exfiltration", "high", "Outbound upload volume > 50MB to unclassified endpoint"),
        ]
        rule_objs = []
        for code, name, cat, sev, logic in rules:
            existing = await db.scalar(select(DetectionRule).where(DetectionRule.org_id == org.id, DetectionRule.rule_id_code == code))
            if not existing:
                r = DetectionRule(org_id=org.id, rule_id_code=code, name=name, category=cat, severity=sev, logic=logic, status="active", matches_count=14)
                db.add(r)
                rule_objs.append(r)

        # 7. Subdomains
        subdomains = [
            ("api.aurora.ai", ["104.21.50.2"], ["Node.js", "Express", "PostgreSQL"], 200, "Aurora Payments API"),
            ("auth.aurora.ai", ["104.21.50.3"], ["Keycloak", "Java", "Spring Boot"], 200, "Sign in — Aurora Identity"),
            ("app.aurora.ai", ["104.21.50.4"], ["React", "Next.js", "Vercel"], 200, "Aurora Internet Banking"),
            ("vpn.aurora.ai", ["104.21.50.6"], ["OpenVPN", "Nginx"], 200, "Aurora VPN Portal"),
            ("staging.aurora.ai", ["104.21.50.15"], ["Nginx", "Docker"], 302, "Staging Gateway"),
        ]
        for domain, ips, techs, sc, title in subdomains:
            existing = await db.scalar(select(Subdomain).where(Subdomain.org_id == org.id, Subdomain.domain == domain))
            if not existing:
                db.add(Subdomain(org_id=org.id, domain=domain, parent_domain="aurora.ai", ips=ips, technologies=techs, status_code=sc, title=title, status="active", discoveries=2))

        # 8. Network Scans
        n_scans = [
            ("203.0.113.0/24", "Port Scan", "completed", 254, 34, 12, "4m 22s"),
            ("104.21.50.0/24", "Service Detect", "completed", 64, 18, 8, "2m 15s"),
        ]
        for tgt, stype, stat, h_cnt, p_cnt, s_cnt, dur in n_scans:
            existing = await db.scalar(select(NetworkScan).where(NetworkScan.org_id == org.id, NetworkScan.target == tgt))
            if not existing:
                db.add(NetworkScan(org_id=org.id, target=tgt, type=stype, status=stat, hosts_count=h_cnt, ports_count=p_cnt, services_count=s_cnt, duration=dur))

        # 9. Code Repositories & Secrets
        repos = [
            ("aurora/core-banking", "github", "https://github.com/aurora/core-banking", "main", "dev-team", 3, 2),
            ("aurora/auth-service", "github", "https://github.com/aurora/auth-service", "main", "security-team", 1, 1),
            ("aurora/infra-terraform", "gitlab", "https://gitlab.com/aurora/infra", "master", "devops", 0, 0),
        ]
        for name, prov, url, branch, owner, fc, sc in repos:
            existing = await db.scalar(select(CodeRepository).where(CodeRepository.org_id == org.id, CodeRepository.url == url))
            if not existing:
                r = CodeRepository(org_id=org.id, name=name, provider=prov, url=url, branch=branch, owner=owner, findings_count=fc, secrets_count=sc, last_scan=utcnow())
                db.add(r)
                await db.flush()
                # add secret finding
                db.add(SecretFinding(org_id=org.id, repo_id=r.id, secret_type="jwt_private_key", description="JWT Signing Secret in configuration", file_path="config/jwt.key", line_number=4, status="open", severity="critical", raw_preview="-----BEGIN RSA PRIVATE KEY-----..."))

        # 10. Security Events
        events = [
            ("auth.failed", "vpn", "medium", "anonymous", "vpn.aurora.ai", "login_failed", "203.0.113.42"),
            ("network.port_scan", "firewall", "low", "external_scanner", "104.21.50.2", "syn_scan", "198.51.100.10"),
            ("api.access_denied", "api_gateway", "high", "compromised_token", "api.aurora.ai/v1/accounts", "forbidden", "203.0.113.42"),
            ("db.query_anomaly", "database", "critical", "service_account", "db.aurora.ai", "bulk_select", "10.0.2.5"),
        ]
        for etype, src, sev, actor, tgt, act, ip in events:
            db.add(SecurityEvent(org_id=org.id, event_type=etype, source=src, severity=sev, actor=actor, target=tgt, action=act, ip_address=ip))

        # 11. Alerts
        alerts_data = [
            ("ALT-1093", "Credential spraying detected against VPN portal", "Authentication", "critical", "open", "Alex Chen"),
            ("ALT-1094", "BOLA API authorization bypass attempted", "API Security", "high", "investigating", "Samira Khan"),
            ("ALT-1095", "Unpatched Apache path traversal exploit signature", "Exploitation", "high", "acknowledged", "Anaya Shah"),
        ]
        for code, title, cat, sev, stat, ass in alerts_data:
            existing = await db.scalar(select(Alert).where(Alert.org_id == org.id, Alert.alert_code == code))
            if not existing:
                db.add(Alert(org_id=org.id, alert_code=code, title=title, category=cat, severity=sev, status=stat, assignee=ass, description=f"Automated detection {title}"))

        # 12. Incidents
        inc_data = [
            ("INC-0042", "Suspected data exfiltration from core banking database", "critical", "open", 2, "Alex Chen", "Exfiltration"),
            ("INC-0041", "Ransomware pre-attack indicators detected on workstation", "critical", "investigating", 1, "Samira Khan", "Impact"),
            ("INC-0040", "Unauthorized domain privilege escalation attempt", "high", "contained", 3, "Anaya Shah", "Privilege Escalation"),
        ]
        for code, title, sev, stat, stage, ass, ttp in inc_data:
            existing = await db.scalar(select(Incident).where(Incident.org_id == org.id, Incident.incident_code == code))
            if not existing:
                inc = Incident(org_id=org.id, incident_code=code, title=title, severity=sev, status=stat, stage=stage, assignee=ass, ttp=ttp, iocs_count=4, assets_count=2, events_count=48)
                db.add(inc)
                await db.flush()
                db.add(IncidentTimeline(incident_id=inc.id, title="Alert escalation", description="Elevated from ALT-1093 to active incident", actor="SOC Automation"))
                db.add(IncidentEvent(incident_id=inc.id, event_type="incident.status_change", description=f"Incident status updated to {stat}", user_name=ass))
                db.add(IncidentAsset(incident_id=inc.id, hostname="db.aurora.ai", impact="compromised"))
                db.add(IncidentIOC(incident_id=inc.id, ioc_type="ip", value="203.0.113.42", description="C2 Command and Control IP"))

        # 13. Response Actions
        actions = [
            ("RA-0045", "Block IP", "203.0.113.42", "completed", "Alex Chen", "Success", "Firewall drop rule applied"),
            ("RA-0044", "Revoke Session", "user:sess_a1b2c3d4", "completed", "Samira Khan", "Success", "Compromised active token revoked"),
            ("RA-0043", "Isolate Endpoint", "host:k8s.aurora.ai", "approved", "Anaya Shah", None, "Quarantine network isolate"),
        ]
        for code, atype, tgt, stat, req_by, res, desc in actions:
            existing = await db.scalar(select(ResponseAction).where(ResponseAction.org_id == org.id, ResponseAction.action_code == code))
            if not existing:
                db.add(ResponseAction(org_id=org.id, action_code=code, type=atype, target=tgt, status=stat, requested_by=req_by, result=res, description=desc))

        # 14. Escalation Policies
        pols = [
            ("Critical incident escalation", "critical", [
                {"delay": "0m", "target": "SOC Team", "channel": "Slack + Email"},
                {"delay": "15m", "target": "SOC Lead", "channel": "Phone + Slack"},
                {"delay": "30m", "target": "CISO", "channel": "Phone + SMS"},
            ]),
            ("High severity triage", "high", [
                {"delay": "0m", "target": "On-call Analyst", "channel": "Slack"},
                {"delay": "30m", "target": "SOC Lead", "channel": "Email"},
            ]),
        ]
        for name, sev, steps in pols:
            existing = await db.scalar(select(EscalationPolicy).where(EscalationPolicy.org_id == org.id, EscalationPolicy.name == name))
            if not existing:
                db.add(EscalationPolicy(org_id=org.id, name=name, severity=sev, steps=steps, incidents_count=12))

        # 15. Integrations
        integrations = [
            ("github", True, "connected", {"repos": 5, "org": "aurora"}),
            ("slack", True, "connected", {"channel": "#soc-alerts"}),
            ("hibp", True, "connected", {"quota": "enterprise"}),
            ("acunetix", True, "connected", {"version": "v24.1"}),
        ]
        for prov, en, stat, cfg in integrations:
            existing = await db.scalar(select(IntegrationConfig).where(IntegrationConfig.org_id == org.id, IntegrationConfig.provider == prov))
            if not existing:
                db.add(IntegrationConfig(org_id=org.id, provider=prov, enabled=en, status=stat, config=cfg, last_sync=utcnow()))

        # 16. Reports & Audit
        reports = [
            ("Executive Security Posture Summary - Q3 2025", "executive", "pdf", "2.4 MB"),
            ("Technical Threat & Vulnerability Audit", "security", "pdf", "4.1 MB"),
            ("Incident Post-Mortem & Timeline (INC-0042)", "incident", "pdf", "1.8 MB"),
        ]
        for title, rtype, fmt, fsize in reports:
            existing = await db.scalar(select(ReportRecord).where(ReportRecord.org_id == org.id, ReportRecord.title == title))
            if not existing:
                db.add(ReportRecord(org_id=org.id, title=title, type=rtype, format=fmt, file_size=fsize, status="generated", created_by="Anaya Shah"))

        audits = [
            ("admin@aurora.ai", "POLICY_UPDATE", "EscalationPolicy:Critical", "Updated timeout threshold to 15m", "104.21.50.1"),
            ("admin@aurora.ai", "ACTION_EXECUTE", "ResponseAction:RA-0045", "Blocked malicious C2 IP 203.0.113.42", "104.21.50.1"),
            ("system", "DISCOVERY_RUN", "DiscoveryJob:subfinder", "Completed subdomain discovery for aurora.ai", "127.0.0.1"),
        ]
        for actor, act, tgt, dtl, ip in audits:
            db.add(AuditLog(org_id=org.id, actor=actor, action=act, target=tgt, detail=dtl, ip_address=ip))

        # 17. AI Investigations
        invs = [
            ("INV-0012", "Analyze data exfiltration indicators and identify affected data scope", "completed", 8, 94),
            ("INV-0011", "Investigate ransomware TTPs and lateral movement patterns", "completed", 4, 88),
        ]
        for code, q, stat, fc, conf in invs:
            existing = await db.scalar(select(AIInvestigation).where(AIInvestigation.org_id == org.id, AIInvestigation.inv_code == code))
            if not existing:
                db.add(AIInvestigation(org_id=org.id, inv_code=code, query=q, status=stat, findings_count=fc, confidence=conf, completed_at=utcnow()))

        await db.commit()
        print("[+] Seeding successfully completed! All tables populated.")


if __name__ == "__main__":
    asyncio.run(seed())
