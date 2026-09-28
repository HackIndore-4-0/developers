import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/ws", tags=["WebSockets"])


@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            payload = {
                "type": "event",
                "event_type": "network.probe",
                "source": "firewall",
                "severity": "low",
                "ip": "203.0.113.15",
                "time": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(4)
    except WebSocketDisconnect:
        pass


@router.websocket("/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await asyncio.sleep(10)
            payload = {
                "type": "alert",
                "alert_code": "ALT-LIVE",
                "title": "Suspicious login attempt detected",
                "severity": "medium",
                "time": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_text(json.dumps(payload))
    except WebSocketDisconnect:
        pass


@router.websocket("/incidents")
async def websocket_incidents(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await asyncio.sleep(15)
            payload = {
                "type": "incident_update",
                "incident_code": "INC-0042",
                "status": "investigating",
                "time": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_text(json.dumps(payload))
    except WebSocketDisconnect:
        pass


@router.websocket("/monitoring")
async def websocket_monitoring(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            payload = {
                "type": "heartbeat",
                "health": "Healthy",
                "latency_ms": 24,
                "time": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass


@router.websocket("/ai-investigation/{id}")
async def websocket_ai_investigation(websocket: WebSocket, id: str):
    await websocket.accept()
    try:
        steps = [
            "Analyzing initial event correlation...",
            "Querying Neo4j attack path graph...",
            "Correlating threat intelligence IOCs...",
            "Formulating containment playbooks...",
            "Investigation complete.",
        ]
        for step in steps:
            await websocket.send_text(json.dumps({"investigation_id": id, "step": step}))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
