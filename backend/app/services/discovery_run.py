"""Discovery runner: executes a DiscoveryJob and upserts findings into Assets."""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security import (
    Asset,
    AssetPort,
    AssetTech,
    DiscoveredHost,
    DiscoveryJob,
    Exposure,
    ExposureEvent,
    Vulnerability,
    VulnerabilityScan,
    utcnow,
)
from app.services.discovery import Finding, get_adapter

VULN_TOOLS = {"nuclei"}
LEAK_TOOLS = {"gitleaks", "leakiq"}


async def run_discovery_job(db: AsyncSession, job: DiscoveryJob) -> DiscoveryJob:
    """Adapters are async; this runs the tool synchronously-ish (await), then persists."""
    import asyncio as _aio

    adapter = get_adapter(job.tool)
    job.status = "running"
    job.started_at = utcnow()
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    try:
        findings = await _aio.wait_for(adapter.run(job.target), timeout=40)
    except _aio.TimeoutError:
        job.status = "failed"
        job.error = "Tool timed out"
        job.finished_at = utcnow()
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        return job
    except Exception as e:  # noqa: BLE001
        job.status = "failed"
        job.error = str(e)[:500]
        job.finished_at = utcnow()
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        return job

    # persist raw discovered hosts
    for f in findings:
        db.add(DiscoveredHost(
            org_id=job.org_id, job_id=job.id, host=f.host, ip=f.ip, type=f.type, data=f.data,
        ))
    await db.flush()

    try:
        # upsert assets
        new_count = await _upsert_assets(db, job, findings)

        # vulns / exposures / scans
        if job.tool in VULN_TOOLS:
            await _upsert_vulns(db, job, findings)
        if job.tool in LEAK_TOOLS:
            await _upsert_leaks(db, job, findings)

        job.findings = len(findings)
        job.progress = 100
        job.status = "completed" if findings else "partial"
        job.finished_at = utcnow()
        job.result = {
            "findings": len(findings),
            "new_assets": new_count,
            "tool": job.tool,
            "target": job.target,
        }
        await db.commit()
    except Exception as e:  # noqa: BLE001
        await db.rollback()
        job.status = "failed"
        job.error = f"persist error: {str(e)[:400]}"
        job.finished_at = utcnow()
        try:
            await db.commit()
        except Exception:
            await db.rollback()

    # best-effort mirror into Neo4j (never blocks the API response)
    try:
        from app.services.sync_graph import sync_org

        await _aio.wait_for(sync_org(db, str(job.org_id)), timeout=15)
    except Exception:  # noqa: BLE001
        pass
    return job


async def _upsert_assets(db: AsyncSession, job: DiscoveryJob, findings: list[Finding]) -> int:
    new_count = 0
    upserted_hostnames = set()

    for f in findings:
        hostname = f.host
        if hostname in upserted_hostnames:
            continue
        upserted_hostnames.add(hostname)

        row = await db.scalar(select(Asset).where(Asset.org_id == job.org_id, Asset.hostname == hostname))
        is_new = row is None
        if row is None:
            row = Asset(
                org_id=job.org_id,
                hostname=hostname,
                domain=hostname if "." in hostname and f.type == "subdomain" else job.target,
                type=f.type or ("subdomain" if "." in hostname else "host"),
                ip=f.ip,
                url=f.data.get("url"),
                discovered_by=job.tool,
                first_seen=utcnow(),
                last_seen=utcnow(),
                tech_stack=f.tech,
                title=f.data.get("title"),
                status_code=f.data.get("status"),
                content_length=f.data.get("content_length"),
            )
            db.add(row)
            new_count += 1
        else:
            row.last_seen = utcnow()
            if f.ip and not row.ip:
                row.ip = f.ip
            if f.tech:
                row.tech_stack = list(set(row.tech_stack or []) | set(f.tech))
            if f.data.get("title"):
                row.title = f.data["title"]
            if f.data.get("status") is not None:
                row.status_code = f.data["status"]
            if f.data.get("content_length") is not None:
                row.content_length = f.data["content_length"]
        await db.flush()

        # ports
        for p in f.ports:
            existing = await db.scalar(
                select(AssetPort).where(
                    AssetPort.asset_id == row.id,
                    AssetPort.port == int(p["port"]),
                    AssetPort.protocol == "tcp",
                )
            )
            if existing:
                existing.service = existing.service or p.get("service")
                existing.last_seen = utcnow()
            else:
                db.add(AssetPort(asset_id=row.id, port=int(p["port"]), protocol="tcp", service=p.get("service")))

        # tech
        for t in f.tech:
            existing = await db.scalar(select(AssetTech).where(AssetTech.asset_id == row.id, AssetTech.name == t))
            if not existing:
                db.add(AssetTech(asset_id=row.id, name=t))

    await db.flush()
    return new_count


async def _upsert_vulns(db: AsyncSession, job: DiscoveryJob, findings: list[Finding]) -> int:
    """Persist nuclei findings as vulnerabilities and a scan record."""
    vuln_count = 0
    scan = None
    for f in findings:
        if not f.vulns:
            continue
        asset = await db.scalar(select(Asset).where(Asset.org_id == job.org_id, Asset.hostname == f.host))
        if not asset:
            continue
        if scan is None:
            scan = VulnerabilityScan(org_id=job.org_id, asset_id=asset.id, job_id=job.id, tool=job.tool)
            db.add(scan)
        for v in f.vulns:
            severity = str(v.get("severity", "info")).lower()
            cve = v.get("cve")
            title = v.get("name") or v.get("template_id") or "Finding"
            existing = await db.scalar(
                select(Vulnerability).where(
                    Vulnerability.org_id == job.org_id,
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.template_id == v.get("template_id"),
                    Vulnerability.title == title,
                )
            )
            if existing:
                existing.last_seen = utcnow()
                existing.evidence = {"matched": v.get("matched")}
                continue
            db.add(Vulnerability(
                org_id=job.org_id, asset_id=asset.id,
                title=title, cve=cve, template_id=v.get("template_id"),
                severity=severity,
                source=job.tool,
                matched_at=v.get("matched"),
                evidence={"matched": v.get("matched"), "template_id": v.get("template_id")},
            ))
            vuln_count += 1
    if scan is not None:
        scan.findings = vuln_count
        scan.status = "completed"
        scan.finished_at = utcnow()
    return vuln_count


def _mask(value: str, keep: int = 4) -> str:
    if not value:
        return value
    m = str(value)
    if len(m) <= keep * 2:
        return "***"
    return f"{m[:keep]}***{m[-3:]}"


async def _upsert_leaks(db: AsyncSession, job: DiscoveryJob, findings: list[Finding]) -> int:
    leak_count = 0
    for f in findings:
        d = f.data or {}
        cat = d.get("category") or (
            "secret" if job.tool == "gitleaks" else d.get("type", "stealer_log")
        )
        identity = d.get("identity") or f.host
        source = d.get("source") or f"gitleaks/{d.get('rule', 'rule')}"
        severity = str(d.get("severity", "medium")).lower()

        existing = await db.scalar(
            select(Exposure).where(
                Exposure.org_id == job.org_id,
                Exposure.affected_identity == identity,
                Exposure.source == source,
            )
        )
        if existing:
            existing.last_seen = utcnow()
            continue
        mask = d.get("secret") or ("***@{domain}" if "@" in str(identity) else "")
        if mask and job.tool == "gitleaks":
            mask = _mask(d["secret"])
        exp = Exposure(
            org_id=job.org_id,
            type=cat,
            affected_identity=str(identity),
            domain=str(identity).split("@")[-1] if "@" in str(identity) else job.target,
            source=source,
            severity=severity,
            mask=mask,
            secret_type=d.get("secret_type"),
            evidence=d,
        )
        db.add(exp)
        await db.flush()  # materialise exp.id before timeline insertion
        db.add(ExposureEvent(exposure_id=exp.id, kind="seen", description=f"Detected by {job.tool}"))
        leak_count += 1
    return leak_count


async def get_job(db: AsyncSession, job_id: str, org_id: str) -> DiscoveryJob | None:
    return await db.scalar(select(DiscoveryJob).where(DiscoveryJob.id == job_id, DiscoveryJob.org_id == org_id))


def job_to_result(job: DiscoveryJob) -> dict:
    return json.loads(json.dumps({
        "id": str(job.id),
        "org_id": str(job.org_id),
        "target": job.target,
        "tool": job.tool,
        "status": job.status,
        "source": job.source,
        "progress": job.progress,
        "findings": job.findings,
        "result": job.result,
        "error": job.error,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }))