import sys
import json
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

print("==========================================================")
print("   FORCE-FIELDS TELEMETRY ENGINE: END-TO-END VERIFICATION  ")
print("==========================================================")

init_db()
client = TestClient(app)

# 1. Test Health Check
res = client.get("/api/v1/health")
assert res.status_code == 200, f"Health check failed: {res.text}"
print("[✓] GET /api/v1/health: OK")

# 2. Test Agent Enrollment (Windows Workstation)
enroll_win_payload = {
    "token": "FORCEFIELDS-DEFAULT-ENROLL-KEY",
    "fingerprint": {
        "hostname": "WIN-SOC-01",
        "os_category": "windows_workstation",
        "os_name": "Windows 11 Pro",
        "os_version": "Windows 11 Pro 23H2 (Build 22631)",
        "ip_address": "192.168.10.15",
        "mac_address": "00:15:5D:8A:2B:11",
        "cpu_percent": 12.5,
        "ram_percent": 45.0,
        "total_ram_mb": 16384,
        "free_ram_mb": 9011
    }
}
res = client.post("/api/v1/agents/enroll", json=enroll_win_payload)
assert res.status_code == 200, f"Win enrollment failed: {res.text}"
win_data = res.json()
win_agent_id = win_data["agent_id"]
win_api_key = win_data["api_key"]
print(f"[✓] POST /api/v1/agents/enroll (Windows): Agent ID = {win_agent_id}")

# 3. Test Agent Enrollment (Ubuntu Server)
enroll_lin_payload = {
    "token": "FORCEFIELDS-DEFAULT-ENROLL-KEY",
    "fingerprint": {
        "hostname": "UBUNTU-SRV-01",
        "os_category": "ubuntu_server",
        "os_name": "Ubuntu",
        "os_version": "Ubuntu 24.04 LTS",
        "ip_address": "192.168.10.20",
        "mac_address": "00:15:5D:8A:2B:22",
        "cpu_percent": 8.0,
        "ram_percent": 30.0,
        "total_ram_mb": 8192,
        "free_ram_mb": 5734
    }
}
res = client.post("/api/v1/agents/enroll", json=enroll_lin_payload)
assert res.status_code == 200, f"Linux enrollment failed: {res.text}"
lin_data = res.json()
lin_agent_id = lin_data["agent_id"]
lin_api_key = lin_data["api_key"]
print(f"[✓] POST /api/v1/agents/enroll (Ubuntu):  Agent ID = {lin_agent_id}")

# 4. Test Heartbeats
hb_win = {
    "agent_id": win_agent_id,
    "hostname": "WIN-SOC-01",
    "os_category": "windows_workstation",
    "os_name": "Windows 11 Pro",
    "os_version": "Windows 11 Pro 23H2",
    "ip_address": "192.168.10.15",
    "cpu_percent": 15.0,
    "ram_percent": 48.0,
    "queue_depth": 0,
    "events_sent_total": 42
}
headers_win = {"X-Agent-ID": win_agent_id, "X-API-Key": win_api_key}
res = client.post("/api/v1/ingest/heartbeat", json=hb_win, headers=headers_win)
assert res.status_code == 200, f"Heartbeat failed: {res.text}"
print("[✓] POST /api/v1/ingest/heartbeat: OK")

# 5. Ingest Windows Sysmon Process Create (Event 1)
win_log_batch = {
    "agent_id": win_agent_id,
    "batch_id": "test-win-batch-001",
    "events": [
        {
            "event_id": "11111111-1111-1111-1111-111111111111",
            "source_channel": "Microsoft-Windows-Sysmon/Operational",
            "source_event_id": "1",
            "event_timestamp": "2026-11-14T03:59:59.890Z",
            "raw_payload": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"invoice.docm\"",
                "ProcessId": "4812",
                "ParentProcessId": "1920",
                "User": "CORP\\ahmed",
                "IntegrityLevel": "Medium",
                "Hashes": "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            }
        },
        {
            "event_id": "22222222-2222-2222-2222-222222222222",
            "source_channel": "Microsoft-Windows-Sysmon/Operational",
            "source_event_id": "3",
            "event_timestamp": "2026-11-14T04:00:01.000Z",
            "raw_payload": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": "4812",
                "Protocol": "tcp",
                "SourceIp": "192.168.10.15",
                "SourcePort": "51422",
                "DestinationIp": "203.0.113.45",
                "DestinationPort": "443",
                "DestinationHostname": "evil-c2.com",
                "User": "CORP\\ahmed"
            }
        }
    ]
}
res = client.post("/api/v1/ingest/logs", json=win_log_batch, headers=headers_win)
assert res.status_code == 200, f"Win log ingest failed: {res.text}"
print(f"[✓] POST /api/v1/ingest/logs (Windows batch): {res.json()}")

# 6. Ingest Linux auditd Execve Event
headers_lin = {"X-Agent-ID": lin_agent_id, "X-API-Key": lin_api_key}
lin_log_batch = {
    "agent_id": lin_agent_id,
    "batch_id": "test-lin-batch-001",
    "events": [
        {
            "event_id": "33333333-3333-3333-3333-333333333333",
            "source_channel": "auditd",
            "source_event_id": "9981",
            "event_timestamp": "2026-11-14T04:00:05.120Z",
            "raw_payload": {
                "syscall": {
                    "exe": "/usr/bin/cat",
                    "pid": "5810",
                    "ppid": "2104",
                    "uid": "0",
                    "euid": "0",
                    "syscall": "59",
                    "success": "yes",
                    "key": "identity"
                },
                "decoded_command_line": "cat /etc/shadow",
                "proc_exe_path": "/usr/bin/cat",
                "proc_exe_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
            }
        }
    ]
}
res = client.post("/api/v1/ingest/logs", json=lin_log_batch, headers=headers_lin)
assert res.status_code == 200, f"Linux log ingest failed: {res.text}"
print(f"[✓] POST /api/v1/ingest/logs (Linux batch): {res.json()}")

# 7. Test Fleet Overview Endpoint
res = client.get("/api/v1/fleet")
assert res.status_code == 200, f"Fleet overview failed: {res.text}"
fleet_data = res.json()
print(f"[✓] GET /api/v1/fleet: Total Agents = {fleet_data['total_agents']} | Online = {fleet_data['online_agents']}")

# 8. Test Log Search and Normalization Verification
res = client.get("/api/v1/logs?limit=10")
assert res.status_code == 200, f"Log search failed: {res.text}"
logs_data = res.json()
print(f"[✓] GET /api/v1/logs: Total Events = {logs_data['total']}")

# Verify Unified JSON Schema Structure on first event
first_event = logs_data["events"][0]
required_keys = ["event_id", "ingest_timestamp", "event_timestamp", "agent", "event", "actor", "process", "network", "file_or_registry", "raw_log_ref", "full_raw_payload"]
for k in required_keys:
    assert k in first_event, f"Missing required unified schema key: {k}"
print(f"[✓] Unified JSON Schema Verified: {first_event['event']['category']} : {first_event['event']['action']}")

# 9. Test Stage 3 AI Consumer Endpoints
res = client.get("/api/v1/ai/unprocessed?limit=10")
assert res.status_code == 200
ai_batch = res.json()
print(f"[✓] GET /api/v1/ai/unprocessed: {ai_batch['count']} unprocessed events ready for AI classifier")

event_ids = [ev["event_id"] for ev in ai_batch["events"]]
res = client.post("/api/v1/ai/ack", json={"event_ids": event_ids})
assert res.status_code == 200
print(f"[✓] POST /api/v1/ai/ack: Acknowledged {res.json()['acknowledged_count']} events")

# Verify AI queue is now empty
res = client.get("/api/v1/ai/unprocessed?limit=10")
assert res.json()["count"] == 0
print("[✓] AI Queue confirmed empty after ACK.")

# 10. Test JSONL Export
res = client.get("/api/v1/ai/export/jsonl")
assert res.status_code == 200
lines = res.text.strip().split("\n")
print(f"[✓] GET /api/v1/ai/export/jsonl: Exported {len(lines)} JSONL records")

print("==========================================================")
print("   ALL VERIFICATIONS PASSED SUCCESSFULLY (100% WORKING)!  ")
print("==========================================================")
