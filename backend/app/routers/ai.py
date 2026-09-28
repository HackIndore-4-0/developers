import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.deps import TenantContext, get_tenant
from app.models.security import AIConversation, AIInvestigation
from app.schemas.domain import (
    AIChatReq,
    AIConversationOut,
    AIInvestigateReq,
    AIInvestigationOut,
)

router = APIRouter(prefix="/ai", tags=["AI & Copilot"])


@router.get("/investigations", response_model=list[AIInvestigationOut])
async def list_ai_investigations(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    stmt = (
        select(AIInvestigation)
        .where(AIInvestigation.org_id == tenant.org.id)
        .order_by(AIInvestigation.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("/investigate", response_model=AIInvestigationOut, status_code=status.HTTP_201_CREATED)
async def create_ai_investigation(
    body: AIInvestigateReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inv = AIInvestigation(
        org_id=tenant.org.id,
        inv_code=f"INV-{uuid.uuid4().hex[:4].upper()}",
        incident_id=body.incident_id,
        query=body.query,
        status="completed",
        findings_count=5,
        confidence=94,
        model=body.model,
        analysis={
            "summary": f"Investigation completed for query: {body.query}",
            "indicators": ["203.0.113.42", "C2 beaconing", "Credential reuse"],
            "risk_level": "High",
        },
        recommendations=[
            "Isolate compromised endpoint WS-ENG-042",
            "Revoke leaked service token",
            "Block IP 203.0.113.42 at perimeter firewall",
        ],
        completed_at=datetime.now(timezone.utc),
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return inv


@router.post("/investigate/{incident_id}", response_model=AIInvestigationOut)
async def investigate_incident_ai(
    incident_id: uuid.UUID,
    body: dict[str, Any] | None = None,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    query = (body or {}).get("query", f"Investigate root cause and blast radius for incident {incident_id}")
    req = AIInvestigateReq(query=query, incident_id=incident_id)
    return await create_ai_investigation(body=req, tenant=tenant, db=db)


@router.get("/investigations/{investigation_id}", response_model=AIInvestigationOut)
async def get_ai_investigation(
    investigation_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    inv = await db.scalar(
        select(AIInvestigation).where(AIInvestigation.id == investigation_id, AIInvestigation.org_id == tenant.org.id)
    )
    if not inv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return inv


@router.post("/analyze-alert", response_model=dict[str, Any])
async def analyze_alert(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "alert_id": body.get("alert_id"),
        "triage_summary": "High likelihood of credential spraying attempt against VPN endpoint.",
        "confidence": 92,
        "recommended_action": "Block source IP and enforce MFA",
    }


@router.post("/analyze-asset", response_model=dict[str, Any])
async def analyze_asset(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "asset_id": body.get("asset_id"),
        "risk_score": 8.4,
        "exposure_summary": "Exposed critical service on public interface with unpatched CVEs.",
        "prioritized_actions": ["Close port 8020", "Upgrade Apache to 2.4.58", "Rotate SSL certificate"],
    }


@router.post("/analyze-vulnerability", response_model=dict[str, Any])
async def analyze_vulnerability(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "vulnerability_id": body.get("vulnerability_id"),
        "exploitability": "Active in-the-wild exploitation detected (CISA KEV)",
        "mitigation": "Apply vendor security advisory patch or restrict network access to trusted CIDRs.",
    }


@router.post("/analyze-exposure", response_model=dict[str, Any])
async def analyze_exposure(
    body: dict[str, Any],
    tenant: TenantContext = Depends(get_tenant),
):
    return {
        "exposure_id": body.get("exposure_id"),
        "risk_assessment": "High impact: Leaked credentials correspond to active administrator account.",
        "immediate_steps": ["Invalidate active session tokens", "Force password reset", "Review audit logs for lateral movement"],
    }


# ---------- AI Chat & Conversations ----------


@router.get("/conversations", response_model=list[AIConversationOut])
async def list_conversations(
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(AIConversation)
        .where(AIConversation.org_id == tenant.org.id)
        .order_by(AIConversation.updated_at.desc())
    )
    result = await db.scalars(stmt)
    return result.all()


@router.post("/chat", response_model=dict[str, Any])
async def ai_chat(
    body: AIChatReq,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    conv = None
    if body.conversation_id:
        conv = await db.scalar(
            select(AIConversation).where(AIConversation.id == body.conversation_id, AIConversation.org_id == tenant.org.id)
        )

    if not conv:
        conv = AIConversation(
            org_id=tenant.org.id,
            title=body.prompt[:40] + ("..." if len(body.prompt) > 40 else ""),
            messages=[],
        )
        db.add(conv)
        await db.flush()

    user_msg = {"role": "user", "content": body.prompt, "time": datetime.now(timezone.utc).strftime("%H:%M")}
    ai_response = (
        f"**SignalThread AI Analysis**:\n\n"
        f"Based on your query: *'{body.prompt}'* and our security graph context:\n"
        f"- We identified potential correlated activity across 2 assets and 1 active incident.\n"
        f"- Recommended next step: Inspect **Response Playbook PB-01** for containment."
    )
    bot_msg = {"role": "assistant", "content": ai_response, "time": datetime.now(timezone.utc).strftime("%H:%M")}

    conv.messages = list(conv.messages) + [user_msg, bot_msg]
    await db.commit()
    await db.refresh(conv)

    return {
        "conversation_id": str(conv.id),
        "reply": ai_response,
        "messages": conv.messages,
    }


@router.get("/conversations/{conversation_id}", response_model=AIConversationOut)
async def get_conversation(
    conversation_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    conv = await db.scalar(
        select(AIConversation).where(AIConversation.id == conversation_id, AIConversation.org_id == tenant.org.id)
    )
    if not conv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    return conv


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(
    conversation_id: uuid.UUID,
    tenant: TenantContext = Depends(get_tenant),
    db: AsyncSession = Depends(get_db),
):
    conv = await db.scalar(
        select(AIConversation).where(AIConversation.id == conversation_id, AIConversation.org_id == tenant.org.id)
    )
    if not conv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    await db.delete(conv)
    await db.commit()
