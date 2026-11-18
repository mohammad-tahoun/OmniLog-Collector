import datetime
import hashlib
import json
import uuid
from typing import Dict, Any, Optional
from dateutil import parser as dt_parser

from app.schemas import (
    UnifiedJSONEvent,
    UnifiedAgent,
    UnifiedEventMetadata,
    RawLogItemSchema
)
from app.normalizer.windows_mapper import map_windows_event
from app.normalizer.linux_mapper import map_linux_event

class NormalizationPipeline:
    def __init__(self):
        # LRU seen set for in-memory batch deduplication
        self.seen_signatures = set()
        self.max_seen_signatures = 50000

    def parse_to_iso8601(self, raw_ts: Optional[str]) -> str:
        """Converts raw heterogeneous timestamps into strict UTC ISO-8601 YYYY-MM-DDTHH:MM:SS.sssZ format."""
        if not raw_ts:
            return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"

        try:
            # Handle Windows / standard ISO strings
            clean_ts = raw_ts.strip().replace("Z", "+00:00")
            dt = dt_parser.parse(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        except Exception:
            return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"

    def compute_signature(self, agent_id: str, channel: str, event_id: str, ts: str, payload: Dict[str, Any]) -> str:
        """Computes SHA-256 fingerprint for deduplication."""
        h = hashlib.sha256()
        h.update(f"{agent_id}:{channel}:{event_id}:{ts}".encode("utf-8"))
        # Add sample of payload
        keys = sorted(payload.keys())[:5]
        for k in keys:
            h.update(f"{k}={payload[k]}".encode("utf-8"))
        return h.hexdigest()

    def normalize(
        self,
        raw_item: RawLogItemSchema,
        agent_id: str,
        hostname: str,
        os_category: str,
        os_version: str,
        ip_address: str,
        raw_log_ref: str
    ) -> Optional[UnifiedJSONEvent]:
        """
        Stage 2 Orchestrator:
        Parsing -> Cleaning -> UTC ISO-8601 -> Deduplication -> Validation -> Unified JSON
        """
        raw_payload = raw_item.raw_payload or {}
        channel = raw_item.source_channel or "generic"
        source_event_id = raw_item.source_event_id or ""

        # 1. UTC ISO-8601 Conversion
        event_timestamp = self.parse_to_iso8601(raw_item.event_timestamp)
        ingest_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"

        # 2. Deduplication check
        sig = self.compute_signature(agent_id, channel, source_event_id, event_timestamp, raw_payload)
        if sig in self.seen_signatures:
            # Duplicate event dropped
            return None

        if len(self.seen_signatures) >= self.max_seen_signatures:
            self.seen_signatures.clear()
        self.seen_signatures.add(sig)

        # 3. Categorized Mapper Delegation
        is_windows = os_category in ["windows_workstation", "windows_server"] or "windows" in channel.lower()
        if is_windows:
            cat, act, out, sev, actor, proc, net, file_reg = map_windows_event(channel, source_event_id, raw_payload)
        else:
            cat, act, out, sev, actor, proc, net, file_reg = map_linux_event(channel, source_event_id, raw_payload)

        # 4. Construct Unified JSON Event
        unified_event = UnifiedJSONEvent(
            event_id=raw_item.event_id or str(uuid.uuid4()),
            ingest_timestamp=ingest_timestamp,
            event_timestamp=event_timestamp,
            agent=UnifiedAgent(
                agent_id=agent_id,
                hostname=hostname,
                os_category=os_category,
                os_version=os_version,
                ip_address=ip_address
            ),
            event=UnifiedEventMetadata(
                source_channel=channel,
                source_event_id=source_event_id or None,
                category=cat,
                action=act,
                outcome=out,
                severity_hint=sev
            ),
            actor=actor,
            process=proc,
            network=net,
            file_or_registry=file_reg,
            raw_log_ref=raw_log_ref,
            full_raw_payload=raw_payload
        )

        return unified_event

pipeline = NormalizationPipeline()
