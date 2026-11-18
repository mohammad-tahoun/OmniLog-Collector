from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field

# Unified JSON Schema Sub-models
class UnifiedAgent(BaseModel):
    agent_id: str
    hostname: str
    os_category: str
    os_version: str
    ip_address: str

class UnifiedEventMetadata(BaseModel):
    source_channel: str
    source_event_id: Optional[str] = None
    category: str # process, network, auth, file_or_registry, system
    action: str
    outcome: str = "success"
    severity_hint: str = "low"

class UnifiedActor(BaseModel):
    user: Optional[str] = None
    user_id: Optional[str] = None
    elevated: bool = False

class UnifiedProcess(BaseModel):
    pid: Optional[int] = None
    ppid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None
    parent_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    hash_sha256: Optional[str] = None

class UnifiedNetwork(BaseModel):
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dns_query: Optional[str] = None

class UnifiedFileOrRegistry(BaseModel):
    target_path: Optional[str] = None
    operation: Optional[str] = None
    details: Optional[str] = None

# Exact Unified JSON Schema for Stage 3 AI Classifier & Hybrid Threat Analysis
class UnifiedJSONEvent(BaseModel):
    event_id: str
    ingest_timestamp: str
    event_timestamp: str
    agent: UnifiedAgent
    event: UnifiedEventMetadata
    actor: UnifiedActor
    process: UnifiedProcess
    network: UnifiedNetwork
    file_or_registry: UnifiedFileOrRegistry
    raw_log_ref: str
    full_raw_payload: Dict[str, Any]

# Agent Enrollment Schemas
class FingerprintPayload(BaseModel):
    hostname: str
    os_category: str
    os_name: str
    os_version: str
    ip_address: str
    mac_address: str
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    total_ram_mb: Optional[int] = 0
    free_ram_mb: Optional[int] = 0

class EnrollRequest(BaseModel):
    token: str
    fingerprint: FingerprintPayload

class EnrollResponse(BaseModel):
    status: str
    agent_id: str
    api_key: str
    os_category: str
    batch_size: int = 100
    heartbeat_interval: int = 10
    message: str

# Heartbeat Ingestion Schema
class HeartbeatRequest(BaseModel):
    agent_id: str
    hostname: str
    os_category: str
    os_name: str
    os_version: str
    ip_address: str
    cpu_percent: float
    ram_percent: float
    queue_depth: int
    events_sent_total: int

class HeartbeatResponse(BaseModel):
    status: str
    acknowledged_at: str

# Ingestion Batch Schemas
class RawLogItemSchema(BaseModel):
    event_id: str
    source_channel: str
    source_event_id: Optional[str] = None
    event_timestamp: str
    raw_payload: Dict[str, Any]
    raw_text: Optional[str] = None

class IngestBatchRequest(BaseModel):
    agent_id: str
    batch_id: str
    events: List[RawLogItemSchema]

class IngestBatchResponse(BaseModel):
    status: str
    received: int
    normalized: int

# Fleet Monitoring Schemas
class DeviceItem(BaseModel):
    agent_id: str
    hostname: str
    os_category: str
    os_name: str
    os_version: str
    ip_address: str
    mac_address: str
    status: str
    cpu_percent: float
    ram_percent: float
    queue_depth: int
    events_sent_total: int
    enrolled_at: str
    last_seen_at: str

class FleetCategoryGroup(BaseModel):
    category: str
    display_name: str
    total_devices: int
    online_count: int
    degraded_count: int
    offline_count: int
    devices: List[DeviceItem]

class FleetSummaryResponse(BaseModel):
    total_agents: int
    online_agents: int
    degraded_agents: int
    offline_agents: int
    categories: Dict[str, FleetCategoryGroup]

# AI Ingestion & Ack Schemas
class AIAckRequest(BaseModel):
    event_ids: List[str]

class AIAckResponse(BaseModel):
    status: str
    acknowledged_count: int
