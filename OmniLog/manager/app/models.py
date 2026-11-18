import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
from app.database import Base

class Device(Base):
    __tablename__ = "devices"

    agent_id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(128), nullable=False, index=True)
    os_category = Column(String(32), nullable=False, index=True) # windows_workstation, windows_server, ubuntu_server, linux_endpoint
    os_name = Column(String(128), nullable=False)
    os_version = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=False)
    mac_address = Column(String(64), nullable=False)
    api_key_hash = Column(String(128), nullable=False)
    status = Column(String(16), default="ONLINE", index=True) # ONLINE, DEGRADED, OFFLINE
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)
    queue_depth = Column(Integer, default=0)
    events_sent_total = Column(Integer, default=0)
    enrolled_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(64), ForeignKey("devices.agent_id"), nullable=False, index=True)
    source_channel = Column(String(128), nullable=False, index=True)
    event_timestamp = Column(String(64), nullable=False)
    raw_payload = Column(Text, nullable=False) # 100% full unedited JSON string
    received_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    event_id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    raw_log_ref = Column(String(64), ForeignKey("raw_logs.id"), nullable=False, index=True)
    ingest_timestamp = Column(String(64), nullable=False, index=True)
    event_timestamp = Column(String(64), nullable=False, index=True)

    # Agent details
    agent_id = Column(String(64), nullable=False, index=True)
    hostname = Column(String(128), nullable=False, index=True)
    os_category = Column(String(32), nullable=False, index=True)
    os_version = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=False)

    # Event classification
    source_channel = Column(String(128), nullable=False, index=True)
    source_event_id = Column(String(32), nullable=True, index=True)
    category = Column(String(32), nullable=False, index=True) # process, network, auth, file_or_registry, system
    action = Column(String(64), nullable=False, index=True) # process_created, network_connect, etc.
    outcome = Column(String(16), default="success", index=True) # success, failure, blocked, unknown
    severity_hint = Column(String(16), default="low", index=True) # low, medium, high, critical

    # Normalized facet JSON payloads
    actor_json = Column(Text, nullable=False) # {"user": ..., "user_id": ..., "elevated": ...}
    process_json = Column(Text, nullable=False) # {"pid": ..., "name": ..., "command_line": ...}
    network_json = Column(Text, nullable=False) # {"protocol": ..., "src_ip": ..., "dst_port": ...}
    file_or_reg_json = Column(Text, nullable=False) # {"target_path": ..., "operation": ...}
    full_raw_payload = Column(Text, nullable=False) # complete original log copy for immediate inspection

    # AI Consumer tracking
    ai_processed = Column(Boolean, default=False, index=True)

Index("idx_normalized_cat_action", NormalizedEvent.category, NormalizedEvent.action)
Index("idx_normalized_agent_time", NormalizedEvent.agent_id, NormalizedEvent.event_timestamp)

class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    token = Column(String(128), primary_key=True)
    description = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)
