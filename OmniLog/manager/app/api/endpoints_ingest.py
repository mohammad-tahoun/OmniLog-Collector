import datetime
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
import app.models as models
from app.schemas import (
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    IngestBatchRequest,
    IngestBatchResponse
)
from app.auth import generate_api_key, hash_api_key, verify_enrollment_token, verify_agent_credentials
from app.normalizer.pipeline import pipeline
from app.services.ai_bridge import ai_bridge

router = APIRouter(tags=["Ingestion & Agents"])

@router.post("/api/v1/agents/enroll", response_model=EnrollResponse)
def enroll_agent(req: EnrollRequest, db: Session = Depends(get_db)):
    verify_enrollment_token(req.token, db)
    fp = req.fingerprint

    # Generate or reuse agent ID
    existing_device = db.query(models.Device).filter(
        (models.Device.hostname == fp.hostname) & (models.Device.mac_address == fp.mac_address)
    ).first()

    raw_api_key = generate_api_key()
    key_hash = hash_api_key(raw_api_key)

    if existing_device:
        agent_id = existing_device.agent_id
        existing_device.api_key_hash = key_hash
        existing_device.os_category = fp.os_category
        existing_device.os_name = fp.os_name
        existing_device.os_version = fp.os_version
        existing_device.ip_address = fp.ip_address
        existing_device.status = "ONLINE"
        existing_device.last_seen_at = datetime.datetime.utcnow()
    else:
        prefix = "win" if "windows" in fp.os_category else "lin"
        short_id = uuid.uuid4().hex[:6]
        agent_id = f"agt-{prefix}-{short_id}"

        new_device = models.Device(
            agent_id=agent_id,
            hostname=fp.hostname,
            os_category=fp.os_category,
            os_name=fp.os_name,
            os_version=fp.os_version,
            ip_address=fp.ip_address,
            mac_address=fp.mac_address,
            api_key_hash=key_hash,
            status="ONLINE",
            cpu_percent=fp.cpu_percent,
            ram_percent=fp.ram_percent,
            queue_depth=0,
            events_sent_total=0,
            enrolled_at=datetime.datetime.utcnow(),
            last_seen_at=datetime.datetime.utcnow()
        )
        db.add(new_device)

    db.commit()

    return EnrollResponse(
        status="enrolled",
        agent_id=agent_id,
        api_key=raw_api_key,
        os_category=fp.os_category,
        batch_size=100,
        heartbeat_interval=10,
        message="Agent enrolled successfully into Force-Fields Fleet."
    )

@router.post("/api/v1/ingest/heartbeat", response_model=HeartbeatResponse)
def ingest_heartbeat(
    req: HeartbeatRequest,
    device: models.Device = Depends(verify_agent_credentials),
    db: Session = Depends(get_db)
):
    device.status = "ONLINE"
    device.cpu_percent = req.cpu_percent
    device.ram_percent = req.ram_percent
    device.queue_depth = req.queue_depth
    device.events_sent_total = req.events_sent_total
    device.ip_address = req.ip_address
    device.last_seen_at = datetime.datetime.utcnow()
    db.commit()

    return HeartbeatResponse(
        status="acknowledged",
        acknowledged_at=datetime.datetime.utcnow().isoformat() + "Z"
    )

@router.post("/api/v1/ingest/logs", response_model=IngestBatchResponse)
async def ingest_logs(
    batch: IngestBatchRequest,
    device: models.Device = Depends(verify_agent_credentials),
    db: Session = Depends(get_db)
):
    normalized_count = 0
    now = datetime.datetime.utcnow()
    device.last_seen_at = now
    device.status = "ONLINE"

    for item in batch.events:
        raw_log_id = str(uuid.uuid4())
        raw_payload_str = json.dumps(item.raw_payload)

        # 1. 100% Full Raw Event Preservation
        raw_record = models.RawLog(
            id=raw_log_id,
            agent_id=device.agent_id,
            source_channel=item.source_channel,
            event_timestamp=item.event_timestamp,
            raw_payload=raw_payload_str,
            received_at=now
        )
        db.add(raw_record)

        # 2. Stage 2 Normalization Pipeline
        normalized_obj = pipeline.normalize(
            raw_item=item,
            agent_id=device.agent_id,
            hostname=device.hostname,
            os_category=device.os_category,
            os_version=device.os_version,
            ip_address=device.ip_address,
            raw_log_ref=raw_log_id
        )

        if normalized_obj:
            norm_record = models.NormalizedEvent(
                event_id=normalized_obj.event_id,
                raw_log_ref=raw_log_id,
                ingest_timestamp=normalized_obj.ingest_timestamp,
                event_timestamp=normalized_obj.event_timestamp,
                agent_id=device.agent_id,
                hostname=device.hostname,
                os_category=device.os_category,
                os_version=device.os_version,
                ip_address=device.ip_address,
                source_channel=normalized_obj.event.source_channel,
                source_event_id=normalized_obj.event.source_event_id,
                category=normalized_obj.event.category,
                action=normalized_obj.event.action,
                outcome=normalized_obj.event.outcome,
                severity_hint=normalized_obj.event.severity_hint,
                actor_json=json.dumps(normalized_obj.actor.model_dump()),
                process_json=json.dumps(normalized_obj.process.model_dump()),
                network_json=json.dumps(normalized_obj.network.model_dump()),
                file_or_reg_json=json.dumps(normalized_obj.file_or_registry.model_dump()),
                full_raw_payload=raw_payload_str,
                ai_processed=False
            )
            db.add(norm_record)
            normalized_count += 1

            # 3. Live Broadcast to AI WebSocket & Redis Consumers
            await ai_bridge.broadcast(normalized_obj)

    db.commit()

    return IngestBatchResponse(
        status="success",
        received=len(batch.events),
        normalized=normalized_count
    )
