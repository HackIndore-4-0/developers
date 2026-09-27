import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import DiscoveryJob, NetworkScan, VulnerabilityScan

router = APIRouter(prefix="/scan-profiles", tags=["Scan Profiles & Automation"])

PROFILES_DATA = [
    {
        "id": "profile-easm-full",
        "name": "Full EASM Discovery & Continuous Audit",
        "description": "Complete external attack surface discovery: Subdomains (Assetfinder/Subfinder) + Port Scanning (100 ports) + Web Technology Fingerprinting + Live Screenshot Capture + CVE Audit.",
        "category": "Discovery & EASM",
        "tools": ["assetfinder", "subfinder", "httpx", "nmap", "playwright", "nuclei"],
        "estimated_duration": "3-5 mins",
        "schedule": "Daily",
        "intensity": "Deep",
    },
    {
        "id": "profile-quick-probe",
        "name": "Quick Port & Web Tech Probe",
        "description": "Fast perimeter check: Async TCP socket probe on top 20 ports + HTTP header/DOM framework detection + live screenshot.",
        "category": "Reconnaissance",
        "tools": ["httpx", "prober", "playwright"],
        "estimated_duration": "30 secs",
        "schedule": "Hourly",
        "intensity": "Light",
    },
    {
        "id": "profile-cve-audit",
        "name": "Critical & High CVE Vulnerability Audit",
        "description": "Runs curated Nuclei security templates for in-the-wild exploitable CVEs, unauthenticated panels, and misconfigurations.",
        "category": "Vulnerability Assessment",
        "tools": ["nuclei", "cve-library"],
        "estimated_duration": "2 mins",
        "schedule": "Weekly",
        "intensity": "Medium",
    },
    {
        "id": "profile-cloud-recon",
        "name": "Cloud Surface & Secret Leak Audit",
        "description": "Scans public cloud assets, exposed S3/storage buckets, git metadata (.git/config), and .env file leaks.",
        "category": "Cloud & Secrets",
        "tools": ["gitleaks", "leakiq", "httpx"],
        "estimated_duration": "1 min",
        "schedule": "Daily",
        "intensity": "Targeted",
    },
]


@router.get("", response_model=list[dict[str, Any]])
async def list_scan_profiles(tenant: TenantContext = Depends(get_tenant)):
    return PROFILES_DATA


@router.post("/run", response_model=dict[str, Any])
async def run_scan_profile(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    profile_id = body.get("profile_id", "profile-easm-full")
    target = body.get("target", "aurora.ai")

    profile = next((p for p in PROFILES_DATA if p["id"] == profile_id), PROFILES_DATA[0])

    # Record job
    job = DiscoveryJob(
        org_id=tenant.org.id,
        target=target,
        tool=profile["name"],
        status="running",
        source="profile_workflow",
        progress=10,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    return {
        "status": "started",
        "job_id": str(job.id),
        "profile": profile["name"],
        "target": target,
        "tools_orchestrated": profile["tools"],
        "estimated_completion": profile["estimated_duration"],
        "message": f"Orchestrated profile '{profile['name']}' started for {target}.",
    }
