import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
import app.models as models

router = APIRouter(tags=["Logs Explorer"])

@router.get("/api/v1/logs")
def search_logs(
    query: Optional[str] = Query(None, description="Free-text search across user, command line, process, and IP"),
    agent_id: Optional[str] = Query(None, description="Filter by Agent ID"),
    os_category: Optional[str] = Query(None, description="Filter by OS category"),
    category: Optional[str] = Query(None, description="Filter by Event category (process, network, auth, etc.)"),
    action: Optional[str] = Query(None, description="Filter by Event action"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    q = db.query(models.NormalizedEvent)

    if agent_id:
        q = q.filter(models.NormalizedEvent.agent_id == agent_id)
    if os_category:
        q = q.filter(models.NormalizedEvent.os_category == os_category)
    if category:
        q = q.filter(models.NormalizedEvent.category == category)
    if action:
        q = q.filter(models.NormalizedEvent.action == action)
    if severity:
        q = q.filter(models.NormalizedEvent.severity_hint == severity)

    if query:
        search_filter = (
            models.NormalizedEvent.hostname.ilike(f"%{query}%") |
            models.NormalizedEvent.process_json.ilike(f"%{query}%") |
            models.NormalizedEvent.actor_json.ilike(f"%{query}%") |
            models.NormalizedEvent.network_json.ilike(f"%{query}%") |
            models.NormalizedEvent.full_raw_payload.ilike(f"%{query}%")
        )
        q = q.filter(search_filter)

    total_count = q.count()
    events = q.order_by(desc(models.NormalizedEvent.event_timestamp)).offset(offset).limit(limit).all()

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
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "events": results
    }

@router.get("/api/v1/logs/{event_id}")
def get_log_by_id(event_id: str, db: Session = Depends(get_db)):
    ev = db.query(models.NormalizedEvent).filter_by(event_id=event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")

    raw_entry = db.query(models.RawLog).filter_by(id=ev.raw_log_ref).first()

    return {
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
        "actor": json.loads(ev.actor_json) if ev.actor_json else {},
        "process": json.loads(ev.process_json) if ev.process_json else {},
        "network": json.loads(ev.network_json) if ev.network_json else {},
        "file_or_registry": json.loads(ev.file_or_reg_json) if ev.file_or_reg_json else {},
        "full_raw_payload": json.loads(ev.full_raw_payload) if ev.full_raw_payload else {},
        "original_raw_log": json.loads(raw_entry.raw_payload) if raw_entry else None
    }
