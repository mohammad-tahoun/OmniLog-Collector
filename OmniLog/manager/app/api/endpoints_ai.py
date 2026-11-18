import json
from typing import List
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc

from app.database import get_db
import app.models as models
from app.schemas import AIAckRequest, AIAckResponse, UnifiedJSONEvent
from app.services.ai_bridge import ai_bridge

router = APIRouter(tags=["AI Consumer & Bridge (Stage 3)"])

@router.get("/api/v1/ai/unprocessed")
def get_unprocessed_batch(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Pulls the oldest unacknowledged normalized JSON events for Force-Fields Stage 3 AI Classifier.
    """
    events = db.query(models.NormalizedEvent).filter(
        models.NormalizedEvent.ai_processed == False
    ).order_by(asc(models.NormalizedEvent.event_timestamp)).limit(limit).all()

    results = []
    for ev in events:
        try:
            actor = json.loads(ev.actor_json) if ev.actor_json else {}
            process = json.loads(ev.process_json) if ev.process_json else {}
            network = json.loads(ev.network_json) if ev.network_json else {}
            file_or_reg = json.loads(ev.file_or_reg_json) if ev.file_or_reg_json else {}
            full_raw = json.loads(ev.full_raw_payload) if ev.full_raw_payload else {}
        except Exception:
            actor, process, network, file_or_reg, full_raw = {}, {}, {}, {}, {}

        results.append({
            "event_id": ev.event_id,
            "raw_log_ref": ev.raw_log_ref,
            "ingest_timestamp": ev.ingest_timestamp,
            "event_timestamp": ev.event_timestamp,
            "agent": {
                "agent_id": ev.agent_id,
                "hostname": ev.hostname,
                "os_category": ev.os_category,
                "os_version": ev.os_version,
                "ip_address": ev.ip_address,
            },
            "event": {
                "source_channel": ev.source_channel,
                "source_event_id": ev.source_event_id,
                "category": ev.category,
                "action": ev.action,
                "outcome": ev.outcome,
                "severity_hint": ev.severity_hint
            },
            "actor": actor,
            "process": process,
            "network": network,
            "file_or_registry": file_or_reg,
            "full_raw_payload": full_raw
        })

    return {
        "count": len(results),
        "limit": limit,
        "events": results
    }

@router.post("/api/v1/ai/ack", response_model=AIAckResponse)
def acknowledge_ai_processed(req: AIAckRequest, db: Session = Depends(get_db)):
    """
    Marks processed event IDs so they are not pulled again.
    """
    if not req.event_ids:
        return AIAckResponse(status="success", acknowledged_count=0)

    updated = db.query(models.NormalizedEvent).filter(
        models.NormalizedEvent.event_id.in_(req.event_ids)
    ).update({models.NormalizedEvent.ai_processed: True}, synchronize_session=False)

    db.commit()
    return AIAckResponse(status="success", acknowledged_count=updated)

@router.get("/api/v1/ai/next-batch")
def get_next_batch(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    """Convenience alias for AI consumers."""
    return get_unprocessed_batch(limit=limit, db=db)

@router.get("/api/v1/ai/export/jsonl")
def export_jsonl(limit: int = Query(5000, ge=1, le=50000), db: Session = Depends(get_db)):
    """
    Exports normalized events as a JSON Lines (JSONL) file for AI model training / offline analysis.
    """
    events = db.query(models.NormalizedEvent).order_by(
        desc(models.NormalizedEvent.event_timestamp)
    ).limit(limit).all()

    def generate_lines():
        for ev in events:
            item = {
                "event_id": ev.event_id,
                "ingest_timestamp": ev.ingest_timestamp,
                "event_timestamp": ev.event_timestamp,
                "agent": {
                    "agent_id": ev.agent_id,
                    "hostname": ev.hostname,
                    "os_category": ev.os_category,
                    "os_version": ev.os_version,
                    "ip_address": ev.ip_address,
                },
                "event": {
                    "source_channel": ev.source_channel,
                    "source_event_id": ev.source_event_id,
                    "category": ev.category,
                    "action": ev.action,
                    "outcome": ev.outcome,
                    "severity_hint": ev.severity_hint
                },
                "actor": json.loads(ev.actor_json) if ev.actor_json else {},
                "process": json.loads(ev.process_json) if ev.process_json else {},
                "network": json.loads(ev.network_json) if ev.network_json else {},
                "file_or_registry": json.loads(ev.file_or_reg_json) if ev.file_or_reg_json else {},
                "raw_log_ref": ev.raw_log_ref
            }
            yield json.dumps(item) + "\n"

    return StreamingResponse(
        generate_lines(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=forcefields_normalized_telemetry.jsonl"}
    )

@router.websocket("/api/v1/ai/stream")
async def websocket_ai_stream(websocket: WebSocket):
    """
    Real-time WebSocket stream delivering live normalized JSON events to Force-Fields AI models.
    """
    await ai_bridge.register(websocket)
    try:
        while True:
            # Keep socket alive and listen for optional ping/filter frames
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ai_bridge.unregister(websocket)
    except Exception:
        ai_bridge.unregister(websocket)
