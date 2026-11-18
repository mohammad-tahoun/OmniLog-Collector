# Force-Fields Telemetry Engine (Central Manager + Dedicated OS Agents)

Production-grade, real-time **Log Collection & Normalization System** for the **Force-Fields AI-SOC** graduation project. This codebase implements **Stage 1 (Granular OS Telemetry Collection)** and **Stage 2 (Preprocessing & Unified JSON Normalization)**, producing standardized, forensic-grade, AI-ready JSON telemetry for downstream **Stage 3 (AI Classification & Hybrid Threat Analysis)**.

---

## 1. Architectural Role & Overview

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                               STAGE 1: COLLECTION                               │
 │                                                                                 │
 │   Windows 10/11 Workstation       Windows Server          Ubuntu Server / Linux │
 │  ┌─────────────────────────┐  ┌────────────────────┐   ┌──────────────────────┐ │
 │  │ Sysmon (Proc, Net, DNS) │  │ AD / Kerberos /    │   │ auditd (execve/hex,  │ │
 │  │ Security (4624, 4688)   │  │   NTLM Auth        │   │   syscall, /proc)    │ │
 │  │ PowerShell ScriptBlock  │  │ RDP / Terminal Srv │   │ auth.log / secure    │ │
 │  │ System & Application    │  │ Defender Firewall  │   │ journald & syslog    │ │
 │  └───────────┬─────────────┘  └─────────┬──────────┘   └──────────┬───────────┘ │
 │              │                          │                         │             │
 │              └──────────────────┐       │       ┌─────────────────┘             │
 │                                 ▼       ▼       ▼                               │
 │                        ┌─────────────────────────────────┐                      │
 │                        │    Persistent Disk FIFO Queue   │                      │
 │                        │  (Zero-loss store-and-forward)  │                      │
 │                        └────────────────┬────────────────┘                      │
 └─────────────────────────────────────────┼───────────────────────────────────────┘
                                           │ HTTPS / TLS (Batched + Heartbeats)
                                           ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                       STAGE 2: CENTRAL MANAGER & NORMALIZATION                  │
 │                                                                                 │
 │  FastAPI Ingestion & Health Monitor (ONLINE / DEGRADED / OFFLINE, 30s threshold)│
 │                                                                                 │
 │       100% Raw Preservation           Unified JSON Normalization Pipeline       │
 │   ┌───────────────────────────┐         ┌───────────────────────────────────┐   │
 │   │ Complete Unmodified Log   │         │ Clean -> ISO-8601 UTC -> Dedupe   │   │
 │   │ (Forensic RawLog Storage) │         │ -> Windows & Linux Mappers        │   │
 │   └───────────────────────────┘         └─────────────────┬─────────────────┘   │
 └───────────────────────────────────────────────────────────┼─────────────────────┘
                                                             │
                                                             ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                        STAGE 3: DOWNSTREAM AI INTEGRATION                       │
 │                                                                                 │
 │  WebSocket Stream: WS /api/v1/ai/stream     REST Queue: GET /api/v1/ai/unprocessed│
 │  AI Ack Tracking: POST /api/v1/ai/ack       Offline Training: /api/v1/ai/export │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```text
forcefields-telemetry/
├── README.md
├── docker-compose.yml
├── bin/                                 # Compiled standalone binaries
│   ├── forcefields-agent-windows-amd64.exe
│   └── forcefields-agent-linux-amd64
├── scripts/
│   ├── setup-windows-telemetry.ps1      # Audit policy, command line, and Sysmon config
│   ├── setup-linux-telemetry.sh         # auditd comprehensive rules, journald, permissions
│   ├── build-agents.sh                  # Cross-compiles Go binaries for Linux & Windows
│   └── build-agents.ps1                 # Native PowerShell cross-compilation script
├── agent/                               # Go Standalone OS Agent
│   ├── go.mod
│   ├── cmd/agent/main.go                # CLI entrypoint (--enroll, --install-service, --run)
│   ├── internal/
│   │   ├── config/config.go             # Agent config reader & YAML writer
│   │   ├── system/fingerprint.go        # Hardware, IP, MAC, RAM, CPU & OS classification
│   │   ├── buffer/queue.go              # Zero-loss persistent disk FIFO queue
│   │   ├── transport/client.go          # Batched HTTPS client & heartbeat worker
│   │   └── collectors/
│   │       ├── collector.go             # Interface and raw event structs
│   │       ├── windows_common.go        # Sysmon, Security, PowerShell, System
│   │       ├── windows_server.go        # AD, Kerberos/NTLM, RDP, DNS, Firewall
│   │       ├── linux_common.go          # auth.log, syslog, journald offset tailer
│   │       └── linux_auditd.go          # Multi-line auditd parser + hex decoder + /proc
├── manager/                             # Python FastAPI Central Manager
│   ├── requirements.txt
│   ├── Dockerfile
│   └── app/
│       ├── main.py                      # FastAPI entrypoint, CORS, static UI serving
│       ├── config.py                    # Settings (offline threshold = 30s)
│       ├── database.py                  # SQLite WAL / PostgreSQL SQLAlchemy session
│       ├── models.py                    # Device, RawLog, NormalizedEvent, EnrollmentToken
│       ├── schemas.py                   # Strict Pydantic Unified JSON schemas
│       ├── auth.py                      # API Key & Enrollment Token validation
│       ├── normalizer/
│       │   ├── pipeline.py              # Stage 2 Normalizer pipeline
│       │   ├── windows_mapper.py        # Windows Security, Sysmon, PowerShell mapper
│       │   └── linux_mapper.py          # Linux auditd, auth, syslog, journald mapper
│       ├── services/
│       │   ├── fleet_monitor.py         # Periodic background health classifier
│       │   └── ai_bridge.py             # Live WebSocket & Redis streaming
│       └── api/
│           ├── endpoints_ingest.py      # /enroll, /heartbeat, /logs
│           ├── endpoints_fleet.py       # /fleet overview & device details
│           ├── endpoints_logs.py        # /logs search, filter, and inspect
│           └── endpoints_ai.py          # /ai/unprocessed, /ai/ack, /ai/stream
└── dashboard/                           # React + Vite + Tailwind CSS Manager UI
    ├── package.json
    ├── vite.config.ts
    ├── dist/index.html                  # Standalone pre-built SOC dashboard
    └── src/
        ├── App.tsx
        └── components/
            ├── FleetOverview.tsx        # OS Category cards + live status badges
            ├── LiveLogStream.tsx        # Granular log stream with filters
            ├── LogInspectorDrawer.tsx   # Normalized AI JSON vs 100% Full Raw Log
            └── AgentEnrollModal.tsx     # Copy-paste deployment command generator
```

---

## 3. Quickstart: Step-by-Step Execution

### Step 1: Start the Central Manager

#### Option A: Native Python (Recommended for fast local testing)
```bash
cd manager
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Option B: Docker Compose
```bash
docker-compose up --build -d
```

- **SOC Web Dashboard**: Open [http://localhost:8000/](http://localhost:8000/) in your browser.
- **Interactive API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Fleet Endpoint**: [http://localhost:8000/api/v1/fleet](http://localhost:8000/api/v1/fleet)

---

### Step 2: Build Standalone OS Agent Binaries

Run the automated cross-compiler script:

#### On Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-agents.ps1
```

#### On Linux / macOS (Bash):
```bash
chmod +x scripts/build-agents.sh
./scripts/build-agents.sh
```

Binaries are compiled cleanly with zero CGo/external dependencies into:
- `bin/forcefields-agent-windows-amd64.exe` (Windows 10/11 & Windows Server)
- `bin/forcefields-agent-linux-amd64` (Ubuntu Server & Linux Endpoints)

---

### Step 3: Configure OS Auditing & Deploy Agents

#### A. Windows 10/11 Workstation & Windows Server

1. **Run Telemetry Setup (Elevated Administrator PowerShell)**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\setup-windows-telemetry.ps1
   ```
   *Enables Advanced Audit Policies (Process Creation with Command Line, Logons, Privileges, Object Access), PowerShell ScriptBlock Logging, and applies the production Sysmon XML profile.*

2. **Enroll the Agent**:
   ```powershell
   .\bin\forcefields-agent-windows-amd64.exe --enroll --manager http://<MANAGER_IP>:8000 --token FORCEFIELDS-DEFAULT-ENROLL-KEY
   ```
   *Auto-detects whether the machine is a `windows_workstation` or `windows_server`, registers hardware fingerprint, receives `agent_id` and `api_key`, and saves `agent.yaml`.*

3. **Run or Install as Windows Service**:
   - **Foreground**: `.\bin\forcefields-agent-windows-amd64.exe --run`
   - **Background Service**: `.\bin\forcefields-agent-windows-amd64.exe --install-service`

---

#### B. Ubuntu Server & Linux Endpoint

1. **Run Telemetry Setup (Root Shell / sudo)**:
   ```bash
   sudo bash scripts/setup-linux-telemetry.sh
   ```
   *Installs auditd, deploys 64/32-bit execve process tracing, identity watches (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`), network connect syscall monitoring, and reloads audit rules.*

2. **Enroll the Agent**:
   ```bash
   sudo ./bin/forcefields-agent-linux-amd64 --enroll --manager http://<MANAGER_IP>:8000 --token FORCEFIELDS-DEFAULT-ENROLL-KEY
   ```
   *Auto-detects `ubuntu_server` vs general `linux_endpoint`, registers IP, MAC, and CPU/RAM metrics.*

3. **Run or Install as systemd Service**:
   - **Foreground**: `sudo ./bin/forcefields-agent-linux-amd64 --run`
   - **Background Daemon**: `sudo ./bin/forcefields-agent-linux-amd64 --install-service`

---

## 4. Unified JSON Normalization Schema (Stage 2)

Every heterogeneous log event from Windows and Linux is converted into this standardized JSON structure:

```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "ingest_timestamp": "2026-11-14T04:00:00.123Z",
  "event_timestamp": "2026-11-14T03:59:59.890Z",
  "agent": {
    "agent_id": "agt-win-01",
    "hostname": "WIN-CLIENT-01",
    "os_category": "windows_workstation",
    "os_version": "Windows 11 Pro 23H2 (Build 22631)",
    "ip_address": "192.168.10.15"
  },
  "event": {
    "source_channel": "Microsoft-Windows-Sysmon/Operational",
    "source_event_id": "1",
    "category": "process",
    "action": "process_created",
    "outcome": "success",
    "severity_hint": "low"
  },
  "actor": {
    "user": "CORP\\ahmed",
    "user_id": "S-1-5-21-...",
    "elevated": false
  },
  "process": {
    "pid": 4812,
    "ppid": 1920,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc ...",
    "parent_name": "winword.exe",
    "parent_command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"invoice.docm\"",
    "hash_sha256": "8f4e2...d91a"
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "192.168.10.15",
    "src_port": 51422,
    "dst_ip": "203.0.113.45",
    "dst_port": 443,
    "dns_query": null
  },
  "file_or_registry": {
    "target_path": null,
    "operation": null,
    "details": null
  },
  "raw_log_ref": "4c0f135b-c2e3-4d43-85e7-2b740529d10e",
  "full_raw_payload": {
    "provider_name": "Microsoft-Windows-Sysmon",
    "event_id": "1",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc ...",
    "Hashes": "SHA256=8F4E2...D91A",
    "User": "CORP\\ahmed"
  }
}
```

---

## 5. Downstream Stage 3 AI Model Consumption

### 1. Real-Time Streaming via WebSocket (`/api/v1/ai/stream`)
```python
import asyncio
import websockets
import json

async def connect_ai_classifier():
    uri = "ws://localhost:8000/api/v1/ai/stream"
    async with websockets.connect(uri) as websocket:
        print("[+] Stage 3 AI connected to real-time telemetry stream.")
        while True:
            raw = await websocket.recv()
            event = json.loads(raw)
            
            # Predict maliciousness using Stage 3 AI Model:
            category = event["event"]["category"]
            cmdline = event["process"]["command_line"]
            actor = event["actor"]["user"]
            
            # Run AI Inference ...
            print(f"[{category}] Host: {event['agent']['hostname']} | Cmd: {cmdline}")

asyncio.run(connect_ai_classifier())
```

### 2. Reliable Batch Pull with Acknowledgment (`/api/v1/ai/unprocessed`)
```python
import requests

# 1. Pull next 100 unprocessed events
resp = requests.get("http://localhost:8000/api/v1/ai/unprocessed?limit=100")
data = resp.json()
events = data["events"]

# 2. Process batch with AI Model
processed_ids = []
for ev in events:
    # Model inference...
    processed_ids.append(ev["event_id"])

# 3. Acknowledge processed IDs so they are not fetched again
requests.post("http://localhost:8000/api/v1/ai/ack", json={"event_ids": processed_ids})
```

---

## 6. Offline Resiliency & Zero-Loss Buffering

When an endpoint loses network connectivity to the Central Manager:
1. The Agent's **Persistent Disk FIFO Queue** (`internal/buffer/queue.go`) buffers incoming events directly to WAL segment files on disk.
2. The agent continuously monitors connection health with exponential backoff (`1s -> 2s -> 4s -> ... -> 30s`).
3. Upon reconnection, the agent flushes buffered events in chronological batches (`50–200` events/batch) until the local queue depth returns to 0.
4. No event is ever lost across network outages or agent restarts.

---

## 7. License
Part of the **Force-Fields AI-SOC** graduation project. All rights reserved.
