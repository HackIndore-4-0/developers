"""SignalThread seed: Aurora Bank demo org + users + assets + ports + tech + certs."""

import asyncio
import sys

from sqlalchemy import select

sys.path.insert(0, ".")

from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models import Organization, OrganizationMember, User  # noqa: E402
from app.models.security import Asset, AssetCert, AssetPort, AssetTech, Exposure, ExposureEvent, Vulnerability, utcnow  # noqa: E402

USERS = [
    {"email": "admin@aurora.ai", "password": "Admin@123", "name": "Anaya Shah", "role": "admin"},
    {"email": "analyst@aurora.ai", "password": "Analyst@123", "name": "Rahul Verma", "role": "analyst"},
    {"email": "viewer@aurora.ai", "password": "Viewer@123", "name": "Meera Iyer", "role": "viewer"},
    {"email": "ops@aurora.ai", "password": "Ops@123", "name": "Liam Doyle", "role": "analyst"},
]

ASSETS = [
    # domain, subdomains
    {"hostname": "aurora.ai", "type": "domain", "domain": "aurora.ai", "ip": "104.21.50.1", "url": "https://aurora.ai",
     "criticality": "critical", "environment": "production", "owner": "platform", "tags": ["dmz", "public"],
     "title": "Aurora Bank — Secure Online Banking", "status_code": 200, "content_length": 184320,
     "tech": ["Cloudflare", "Nginx", "React"], "ports": [(443, "https", "nginx 1.24"), (80, "http", "nginx 1.24")],
     "cert": ("*.aurora.ai", "DigiCert SHA2", ["aurora.ai", "*.aurora.ai"], 2027)},
    {"hostname": "api.aurora.ai", "type": "api", "domain": "aurora.ai", "ip": "104.21.50.2", "url": "https://api.aurora.ai",
     "criticality": "critical", "environment": "production", "owner": "backend", "tags": ["public", "api"],
     "title": "Aurora Payments API", "status_code": 200, "content_length": 92160,
     "tech": ["Node.js", "Express", "PostgreSQL", "Redis"], "ports": [(443, "https", "nodejs/express"), (8080, "http-proxy", "Jetty")],
     "cert": ("api.aurora.ai", "Let's Encrypt", ["api.aurora.ai"], 2026)},
    {"hostname": "auth.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "104.21.50.3", "url": "https://auth.aurora.ai",
     "criticality": "critical", "environment": "production", "owner": "backend", "tags": ["auth", "public"],
     "title": "Sign in — Aurora Identity", "status_code": 200, "content_length": 51200,
     "tech": ["Keycloak", "Java", "Spring Boot"], "ports": [(443, "https", "keycloak")], "cert": ("auth.aurora.ai", "Let's Encrypt", ["auth.aurora.ai"], 2026)},
    {"hostname": "app.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "104.21.50.4", "url": "https://app.aurora.ai",
     "criticality": "high", "environment": "production", "owner": "frontend", "tags": ["public"],
     "title": "Aurora Internet Banking", "status_code": 200, "content_length": 142502,
     "tech": ["React", "Next.js", "Vercel"], "ports": [(443, "https", "next")], "cert": ("app.aurora.ai", "Let's Encrypt", ["app.aurora.ai"], 2026)},
    {"hostname": "mail.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "104.21.50.5", "url": "https://mail.aurora.ai",
     "criticality": "medium", "environment": "production", "owner": "infra", "tags": ["mail"],
     "title": "Roundcube Webmail Login", "status_code": 200, "content_length": 22016,
     "tech": ["Postfix", "Dovecot", "Roundcube"], "ports": [(25, "smtp", "postfix"), (465, "smtps", "postfix")]},
    {"hostname": "vpn.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "104.21.50.6", "url": "https://vpn.aurora.ai",
     "criticality": "critical", "environment": "production", "owner": "infra", "tags": ["vpn", "remote"],
     "title": "Aurora VPN Portal", "status_code": 200, "content_length": 13312,
     "tech": ["OpenVPN", "Nginx"], "ports": [(1194, "openvpn", "OpenVPN"), (443, "https", "nginx")]},
    {"hostname": "dev.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "10.0.1.10", "url": "https://dev.aurora.ai",
     "criticality": "low", "environment": "development", "owner": "engineering", "tags": ["dev"],
     "title": "Jenkins — Build Server", "status_code": 200, "content_length": 118784,
     "tech": ["Jenkins", "GitLab"], "ports": [(8080, "http-proxy", "jenkins")]},
    {"hostname": "grafana.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "10.0.1.11", "url": "https://grafana.aurora.ai",
     "criticality": "medium", "environment": "staging", "owner": "platform", "tags": ["monitoring"],
     "title": "Grafana", "status_code": 302, "content_length": 8192,
     "tech": ["Grafana", "Prometheus"], "ports": [(3000, "http", "grafana")]},
    {"hostname": "git.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "10.0.1.12", "url": "https://git.aurora.ai",
     "criticality": "high", "environment": "production", "owner": "engineering", "tags": ["cicd"],
     "title": "GitLab", "status_code": 200, "content_length": 65728,
     "tech": ["GitLab"], "ports": [(22, "ssh", "openssh"), (443, "https", "gitlab")]},
    # some IP assets
    {"hostname": "203.0.113.5", "type": "ip", "ip": "203.0.113.5", "url": "http://203.0.113.5",
     "criticality": "medium", "environment": "production", "owner": "infra", "tags": ["edge"],
     "title": "Haproxy Stats", "status_code": 200, "content_length": 40960,
     "tech": ["Haproxy"], "ports": [(80, "http", "haproxy"), (443, "https", "haproxy")]},
    {"hostname": "203.0.113.9", "type": "ip", "ip": "203.0.113.9", "url": "http://203.0.113.9",
     "criticality": "low", "environment": "production", "owner": "infra", "tags": ["legacy"],
     "title": "Apache Default Page", "status_code": 200, "content_length": 24680,
     "tech": ["Apache 2.4", "PHP"], "ports": [(80, "http", "apache")]},
    {"hostname": "db.aurora.ai", "type": "subdomain", "domain": "aurora.ai", "ip": "10.0.2.5",
     "criticality": "critical", "environment": "production", "owner": "backend", "tags": ["database", "internal"],
     "title": "db.aurora.ai", "status_code": None, "content_length": None,
     "tech": ["PostgreSQL"], "ports": [(5432, "postgresql", "postgres 15")]},
]


async def main() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.slug == "aurora-bank"))
        if not org:
            org = Organization(name="Aurora Bank", slug="aurora-bank", description="Demo financial org")
            db.add(org)
            await db.flush()

            for spec in USERS:
                user = User(email=spec["email"], password_hash=hash_password(spec["password"]), name=spec["name"])
                db.add(user)
                await db.flush()
                db.add(OrganizationMember(org_id=org.id, user_id=user.id, role=spec["role"]))

        # assets (upsert by hostname — enrich on repeat runs)
        asset_count = 0
        for a in ASSETS:
            existing = await db.scalar(select(Asset).where(Asset.org_id == org.id, Asset.hostname == a["hostname"]))
            if existing:
                existing.url = a.get("url", existing.url)
                existing.title = a.get("title", existing.title)
                existing.status_code = a.get("status_code", existing.status_code)
                existing.content_length = a.get("content_length", existing.content_length)
                existing.tech_stack = a.get("tech", existing.tech_stack)
                existing.tags = a.get("tags", existing.tags)
                existing.owner = a.get("owner", existing.owner)
                existing.ip = a.get("ip", existing.ip)
                continue
            asset = Asset(
                org_id=org.id, hostname=a["hostname"], domain=a.get("domain"), type=a["type"], ip=a.get("ip"),
                url=a.get("url"), criticality=a["criticality"], environment=a.get("environment", "production"),
                owner=a.get("owner"), tags=a.get("tags", []), tech_stack=a.get("tech", []),
                title=a.get("title"), status_code=a.get("status_code"), content_length=a.get("content_length"),
                discovered_by="seed", first_seen=utcnow(), last_seen=utcnow(),
            )
            db.add(asset)
            await db.flush()
            asset_count += 1

            for port, service, version in a.get("ports", []):
                db.add(AssetPort(asset_id=asset.id, port=port, protocol="tcp", service=service, last_seen=utcnow()))
            for t in a.get("tech", []):
                db.add(AssetTech(asset_id=asset.id, name=t))
            if c := a.get("cert"):
                db.add(AssetCert(asset_id=asset.id, subject_cn=c[0], issuer_cn=c[1], san=c[2],
                                 expires_at=utcnow().replace(year=c[3]), fingerprint="seed-cert"))

        # vulnerabilities (anchor to known assets)
        vulns_seed = [
            ("api.aurora.ai", "Broken Object Level Authorization in /v1/transactions", "CVE-2024-5345", "critical", 9.8, "CWE-639", "open", "nuclei"),
            ("api.aurora.ai", ".env file exposed via misconfigured static mount", None, "high", 7.5, "CWE-538", "open", "nuclei"),
            ("auth.aurora.ai", "Keycloak SSRF in authorization endpoint", "CVE-2025-2041", "high", 8.8, "CWE-918", "open", "nuclei"),
            ("vpn.aurora.ai", "CVE-2023-4681 OpenVPN heap overflow", "CVE-2023-4681", "high", 8.1, "CWE-122", "open", "nuclei"),
            ("app.aurora.ai", "Reflected XSS in search parameter", "CVE-2024-2214", "medium", 6.1, "CWE-79", "open", "nuclei"),
            ("git.aurora.ai", "GitLab unauthenticated DoS via cached open redirect", "CVE-2024-45409", "medium", 6.5, "CWE-601", "open", "nuclei"),
            ("203.0.113.9", "Apache 2.4.49 path traversal (RCE)", "CVE-2021-41773", "critical", 9.8, "CWE-22", "open", "nuclei"),
            ("grafana.aurora.ai", "Grafana unauthenticated file read via /public", "CVE-2024-9264", "medium", 5.3, "CWE-22", "open", "nuclei"),
        ]
        vuln_count = 0
        for host, title, cve, sev, cvss, cwe, status, source in vulns_seed:
            asset = await db.scalar(select(Asset).where(Asset.org_id == org.id, Asset.hostname == host))
            if not asset:
                continue
            existing = await db.scalar(
                select(Vulnerability).where(
                    Vulnerability.org_id == org.id,
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.title == title,
                )
            )
            if existing:
                continue
            db.add(Vulnerability(
                org_id=org.id, asset_id=asset.id, title=title, cve=cve, severity=sev,
                cvss=cvss, cwe=cwe, status=status, source=source,
                template_id=f"cves/{cve}" if cve else None,
                remediation="Upgrade component and apply vendor patch; validate authorization on object IDs.",
                evidence={"discovered": "seed", "matched": f"https://{host}"},
            ))
            vuln_count += 1

        # exposures (leak intelligence)
        exps_seed = [
            ("credential", "ops@aurora.ai", "aurora.ai", "StealerLog/RedLine-2024", "critical", "ops***ai", "password"),
            ("api_key", "admin@aurora.ai", "aurora.ai", "PasteSite/heapdump-2023", "high", "ad***ai", "firebase"),
            ("breach", "aurora-bank.com", "aurora-bank.com", "2019-credit-union-breach", "high", "au***om", None),
            ("credential", "analyst@aurora.ai", "aurora.ai", "StealerLog/Vidar-2023", "medium", "an***ai", "email-password"),
            ("stealer_log", "root@aurora.ai", "aurora.ai", "StealerLog/Stealc-2025", "high", "ro***ai", "session-cookie"),
            ("source_code", "github/aurora-payments", "aurora.ai", "public-repo-mirror", "medium", "gi***nts", None),
        ]
        exp_count = 0
        for etype, identity, domain, source, sev, mask, stype in exps_seed:
            existing = await db.scalar(
                select(Exposure).where(
                    Exposure.org_id == org.id,
                    Exposure.affected_identity == identity,
                    Exposure.source == source,
                )
            )
            if existing:
                continue
            exp = Exposure(
                org_id=org.id, type=etype, affected_identity=identity, domain=domain,
                source=source, severity=sev, mask=mask, secret_type=stype,
                evidence={"seed": True, "source_detail": source},
            )
            db.add(exp)
            await db.flush()
            db.add(ExposureEvent(exposure_id=exp.id, kind="seen", description=f"First observed in {source}"))
            exp_count += 1

        await db.commit()
        print(f"Seed ok: org={org.slug} assets={asset_count} vulns={vuln_count} exposures={exp_count}")

        # mirror into Neo4j (best-effort)
        from app.services.sync_graph import sync_org

        try:
            result = await sync_org(db, str(org.id))
            print(f"Graph sync: {result}")
        except Exception as e:  # noqa: BLE001
            print(f"Graph sync skipped ({e})")


if __name__ == "__main__":
    asyncio.run(main())