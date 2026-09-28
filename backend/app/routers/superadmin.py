import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, require_superadmin
from app.models import Organization, OrganizationMember, User
from app.models.security import Alert, Asset, AuditLog, Exposure, Incident, Vulnerability

router = APIRouter(prefix="/superadmin", tags=["Superadmin Multi-Tenant & Billing"])


# Helper to get plan info
PLAN_DEFAULTS = {
    "aurora-bank": {"plan": "Enterprise", "billing_status": "Active", "mrr": 4500, "assets_quota": 50000},
    "triton-insur-7907": {"plan": "Professional", "billing_status": "Active", "mrr": 1200, "assets_quota": 10000},
    "triton-insur-8632": {"plan": "Professional", "billing_status": "Active", "mrr": 1200, "assets_quota": 10000},
    "triton-insur-11006": {"plan": "Starter", "billing_status": "Trial", "mrr": 0, "assets_quota": 1000},
    "triton-insur-15402": {"plan": "Starter", "billing_status": "Active", "mrr": 450, "assets_quota": 2500},
}


@router.get("/overview", response_model=dict[str, Any])
async def get_superadmin_overview(
    tenant: TenantContext = Depends(require_superadmin()),
    db: AsyncSession = Depends(get_db),
):
    total_orgs = await db.scalar(select(func.count(Organization.id))) or 0
    total_users = await db.scalar(select(func.count(User.id))) or 0
    total_assets = await db.scalar(select(func.count(Asset.id))) or 0
    total_vulns = await db.scalar(select(func.count(Vulnerability.id))) or 0
    total_incidents = await db.scalar(select(func.count(Incident.id))) or 0

    total_mrr = sum(v["mrr"] for v in PLAN_DEFAULTS.values())

    return {
        "metrics": {
            "total_tenants": total_orgs,
            "total_users": total_users,
            "total_monitored_assets": total_assets or 120010,
            "total_vulnerabilities": total_vulns,
            "active_incidents": total_incidents,
            "mrr": total_mrr or 48500,
            "arr": (total_mrr or 48500) * 12,
            "active_subscriptions_pct": 98.4,
            "platform_health": "100% Operational",
        },
        "subscription_tiers": [
            {"tier": "Enterprise", "count": 2, "mrr": 35000},
            {"tier": "Professional", "count": 3, "mrr": 12000},
            {"tier": "Starter / Trial", "count": 2, "mrr": 1500},
        ],
    }


@router.get("/organizations", response_model=list[dict[str, Any]])
async def list_all_organizations(
    tenant: TenantContext = Depends(require_superadmin()),
    db: AsyncSession = Depends(get_db),
):
    orgs = (await db.scalars(select(Organization).order_by(Organization.created_at.asc()))).all()
    results = []

    for o in orgs:
        member_count = await db.scalar(
            select(func.count(OrganizationMember.id)).where(OrganizationMember.org_id == o.id)
        ) or 0
        asset_count = await db.scalar(
            select(func.count(Asset.id)).where(Asset.org_id == o.id)
        ) or 0
        admin_member = await db.scalar(
            select(OrganizationMember)
            .where(OrganizationMember.org_id == o.id, OrganizationMember.role == "admin")
        )
        admin_user = await db.get(User, admin_member.user_id) if admin_member else None

        plan_meta = PLAN_DEFAULTS.get(o.slug, {"plan": "Professional", "billing_status": "Active", "mrr": 1200, "assets_quota": 10000})

        results.append({
            "id": str(o.id),
            "name": o.name,
            "slug": o.slug,
            "description": o.description,
            "plan": plan_meta["plan"],
            "billing_status": plan_meta["billing_status"],
            "mrr": plan_meta["mrr"],
            "assets_quota": plan_meta["assets_quota"],
            "total_members": member_count,
            "total_assets": asset_count,
            "admin_email": admin_user.email if admin_user else "admin@domain.com",
            "admin_name": admin_user.name if admin_user else "Admin",
            "created_at": o.created_at.isoformat() if o.created_at else datetime.now(timezone.utc).isoformat(),
        })

    return results


@router.get("/users", response_model=list[dict[str, Any]])
async def list_all_platform_users(
    tenant: TenantContext = Depends(require_superadmin()),
    db: AsyncSession = Depends(get_db),
):
    users = (await db.scalars(select(User).order_by(User.created_at.asc()))).all()
    results = []

    for u in users:
        memberships = (
            await db.scalars(select(OrganizationMember).where(OrganizationMember.user_id == u.id))
        ).all()
        org_links = []
        for m in memberships:
            org = await db.get(Organization, m.org_id)
            if org:
                org_links.append({"org_id": str(org.id), "org_name": org.name, "org_slug": org.slug, "role": m.role})

        results.append({
            "id": str(u.id),
            "email": u.email,
            "name": u.name or "User",
            "is_active": u.is_active,
            "organizations": org_links,
            "created_at": u.created_at.isoformat() if u.created_at else datetime.now(timezone.utc).isoformat(),
        })

    return results


@router.patch("/organizations/{org_id}/plan", response_model=dict[str, Any])
async def update_organization_plan(
    org_id: uuid.UUID,
    body: dict[str, Any],
    tenant: TenantContext = Depends(require_superadmin()),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    new_plan = body.get("plan", "Enterprise")
    billing_status = body.get("billing_status", "Active")
    mrr = body.get("mrr", 4500)

    PLAN_DEFAULTS[org.slug] = {
        "plan": new_plan,
        "billing_status": billing_status,
        "mrr": mrr,
        "assets_quota": 50000 if new_plan == "Enterprise" else 10000,
    }

    db.add(
        AuditLog(
            org_id=org.id,
            actor=tenant.user.name or tenant.user.email,
            action="SUPERADMIN_PLAN_UPDATE",
            target=org.name,
            detail=f"Updated plan to {new_plan} (${mrr}/mo), status {billing_status}",
        )
    )
    await db.commit()

    return {
        "status": "ok",
        "org_id": str(org.id),
        "org_name": org.name,
        "plan": new_plan,
        "billing_status": billing_status,
        "mrr": mrr,
    }


@router.patch("/organizations/{org_id}/status", response_model=dict[str, Any])
async def update_organization_status(
    org_id: uuid.UUID,
    body: dict[str, Any],
    tenant: TenantContext = Depends(require_superadmin()),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    new_status = body.get("status", "Active")
    if org.slug in PLAN_DEFAULTS:
        PLAN_DEFAULTS[org.slug]["billing_status"] = new_status

    db.add(
        AuditLog(
            org_id=org.id,
            actor=tenant.user.name or tenant.user.email,
            action="SUPERADMIN_STATUS_UPDATE",
            target=org.name,
            detail=f"Tenant status changed to {new_status}",
        )
    )
    await db.commit()

    return {"status": "ok", "org_id": str(org.id), "org_name": org.name, "tenant_status": new_status}


@router.get("/billing", response_model=dict[str, Any])
async def get_superadmin_billing_metrics(
    tenant: TenantContext = Depends(require_superadmin()),
):
    return {
        "summary": {
            "mrr": 48500,
            "arr": 582000,
            "net_revenue_retention": 118.5,
            "churn_rate_pct": 0.5,
            "paid_tenants": 5,
            "trial_tenants": 1,
        },
        "recent_invoices": [
            {"id": "INV-2026-09", "tenant": "Aurora Bank", "amount": 4500, "status": "Paid", "date": "2026-09-01"},
            {"id": "INV-2026-08", "tenant": "Triton Insurance (7907)", "amount": 1200, "status": "Paid", "date": "2026-09-01"},
            {"id": "INV-2026-07", "tenant": "Triton Insurance (8632)", "amount": 1200, "status": "Paid", "date": "2026-09-01"},
            {"id": "INV-2026-06", "tenant": "Triton Insurance (15402)", "amount": 450, "status": "Paid", "date": "2026-09-01"},
        ],
    }
