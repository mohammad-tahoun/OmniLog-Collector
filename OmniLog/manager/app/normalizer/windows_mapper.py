import os
import re
from typing import Dict, Any, Tuple
from app.schemas import UnifiedActor, UnifiedProcess, UnifiedNetwork, UnifiedFileOrRegistry

def extract_hash(hash_str: str, hash_type: str = "SHA256") -> str:
    if not hash_str:
        return ""
    pattern = rf"{hash_type}=([A-Fa-f0-9]{{64}})"
    match = re.search(pattern, hash_str)
    if match:
        return match.group(1).lower()
    # Check if raw hex
    if len(hash_str) == 64 and re.match(r"^[A-Fa-f0-9]{64}$", hash_str):
        return hash_str.lower()
    return ""

def map_windows_event(
    channel: str,
    event_id: str,
    payload: Dict[str, Any]
) -> Tuple[str, str, str, str, UnifiedActor, UnifiedProcess, UnifiedNetwork, UnifiedFileOrRegistry]:
    """
    Maps Windows Security, Sysmon, PowerShell, and Server logs to Unified Schema components.
    Returns: (category, action, outcome, severity_hint, actor, process, network, file_or_reg)
    """
    category = "system"
    action = "system_event"
    outcome = "success"
    severity_hint = "low"

    actor = UnifiedActor()
    process = UnifiedProcess()
    network = UnifiedNetwork()
    file_or_reg = UnifiedFileOrRegistry()

    # Extract event data fields
    event_data = payload.get("event_data", {})
    if not isinstance(event_data, dict):
        event_data = {}

    def get_val(key: str, default: str = "") -> str:
        return str(event_data.get(key) or payload.get(key) or default)

    # -------------------------------------------------------------
    # 1. SYSMON CHANNELS (Microsoft-Windows-Sysmon/Operational)
    # -------------------------------------------------------------
    if "sysmon" in channel.lower():
        if event_id == "1": # Process Creation
            category = "process"
            action = "process_created"
            outcome = "success"
            severity_hint = "low"

            image = get_val("Image")
            cmdline = get_val("CommandLine")
            parent_image = get_val("ParentImage")
            parent_cmdline = get_val("ParentCommandLine")
            hashes = get_val("Hashes")
            user = get_val("User")
            pid_str = get_val("ProcessId")
            ppid_str = get_val("ParentProcessId")
            integrity = get_val("IntegrityLevel")

            pid = int(pid_str) if pid_str.isdigit() else None
            ppid = int(ppid_str) if ppid_str.isdigit() else None

            process = UnifiedProcess(
                pid=pid,
                ppid=ppid,
                name=os.path.basename(image) if image else None,
                executable=image,
                command_line=cmdline,
                parent_name=os.path.basename(parent_image) if parent_image else None,
                parent_command_line=parent_cmdline,
                hash_sha256=extract_hash(hashes, "SHA256")
            )
            actor = UnifiedActor(
                user=user or None,
                user_id=payload.get("user_sid") or None,
                elevated=integrity.lower() in ["high", "system"]
            )

        elif event_id == "3": # Network Connection
            category = "network"
            action = "network_connect"
            outcome = "success"
            severity_hint = "low"

            src_ip = get_val("SourceIp")
            dst_ip = get_val("DestinationIp")
            src_p = get_val("SourcePort")
            dst_p = get_val("DestinationPort")
            proto = get_val("Protocol").lower()
            dst_host = get_val("DestinationHostname")

            network = UnifiedNetwork(
                protocol=proto or "tcp",
                src_ip=src_ip or None,
                src_port=int(src_p) if src_p.isdigit() else None,
                dst_ip=dst_ip or None,
                dst_port=int(dst_p) if dst_p.isdigit() else None,
                dns_query=dst_host or None
            )

            image = get_val("Image")
            pid_str = get_val("ProcessId")
            process = UnifiedProcess(
                pid=int(pid_str) if pid_str.isdigit() else None,
                name=os.path.basename(image) if image else None,
                executable=image
            )
            actor = UnifiedActor(user=get_val("User") or None)

        elif event_id == "10": # Process Access
            category = "process"
            action = "process_access"
            severity_hint = "medium"
            src_image = get_val("SourceImage")
            tgt_image = get_val("TargetImage")
            process = UnifiedProcess(
                name=os.path.basename(src_image) if src_image else None,
                executable=src_image,
                parent_name=os.path.basename(tgt_image) if tgt_image else None
            )

        elif event_id in ["11", "23", "26"]: # File Create / Delete
            category = "file_or_registry"
            action = "file_create" if event_id == "11" else "file_delete"
            target_path = get_val("TargetFilename")
            file_or_reg = UnifiedFileOrRegistry(
                target_path=target_path or None,
                operation="create" if event_id == "11" else "delete"
            )
            image = get_val("Image")
            process = UnifiedProcess(executable=image, name=os.path.basename(image) if image else None)

        elif event_id in ["12", "13", "14"]: # Registry
            category = "file_or_registry"
            action = "registry_event"
            target_obj = get_val("TargetObject")
            file_or_reg = UnifiedFileOrRegistry(
                target_path=target_obj or None,
                operation=get_val("EventType") or "modify",
                details=get_val("Details") or None
            )

        elif event_id == "22": # DNS Query
            category = "network"
            action = "dns_query"
            query_name = get_val("QueryName")
            network = UnifiedNetwork(
                protocol="udp",
                dst_port=53,
                dns_query=query_name or None
            )
            image = get_val("Image")
            process = UnifiedProcess(name=os.path.basename(image) if image else None, executable=image)

    # -------------------------------------------------------------
    # 2. WINDOWS SECURITY CHANNEL
    # -------------------------------------------------------------
    elif channel.lower() == "security":
        if event_id == "4624": # Logon Success
            category = "auth"
            action = "logon_success"
            outcome = "success"
            severity_hint = "low"

            user = get_val("TargetUserName")
            domain = get_val("TargetDomainName")
            ip = get_val("IpAddress")
            port = get_val("IpPort")
            sid = get_val("TargetUserSid")
            logon_type = get_val("LogonType")

            full_user = f"{domain}\\{user}" if domain and domain != "-" else user
            actor = UnifiedActor(
                user=full_user or None,
                user_id=sid or None,
                elevated=logon_type in ["2", "10"]
            )
            network = UnifiedNetwork(
                src_ip=ip if ip and ip != "-" else None,
                src_port=int(port) if port and port.isdigit() else None
            )

        elif event_id == "4625": # Logon Failure
            category = "auth"
            action = "logon_failure"
            outcome = "failure"
            severity_hint = "medium"

            user = get_val("TargetUserName")
            domain = get_val("TargetDomainName")
            ip = get_val("IpAddress")
            sid = get_val("TargetUserSid")

            full_user = f"{domain}\\{user}" if domain and domain != "-" else user
            actor = UnifiedActor(user=full_user or None, user_id=sid or None)
            network = UnifiedNetwork(src_ip=ip if ip and ip != "-" else None)

        elif event_id == "4634": # Logoff
            category = "auth"
            action = "logoff"
            outcome = "success"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)

        elif event_id == "4672": # Special Privileges
            category = "auth"
            action = "special_privileges_assigned"
            actor = UnifiedActor(user=get_val("SubjectUserName") or None, elevated=True)

        elif event_id == "4688": # Process Creation
            category = "process"
            action = "process_created"
            new_proc = get_val("NewProcessName")
            cmd = get_val("CommandLine")
            parent_proc = get_val("ParentProcessName")
            actor = UnifiedActor(user=get_val("SubjectUserName") or None)
            process = UnifiedProcess(
                name=os.path.basename(new_proc) if new_proc else None,
                executable=new_proc or None,
                command_line=cmd or None,
                parent_name=os.path.basename(parent_proc) if parent_proc else None
            )

        elif event_id == "4697": # Service Installed
            category = "system"
            action = "service_installed"
            severity_hint = "medium"
            svc_name = get_val("ServiceName")
            svc_file = get_val("ServiceFileName")
            file_or_reg = UnifiedFileOrRegistry(target_path=svc_name, operation="service_install", details=svc_file)
            process = UnifiedProcess(executable=svc_file)

        elif event_id in ["4720", "4722", "4724", "4728", "4732"]: # User / Group Management
            category = "auth"
            action = "user_group_management"
            severity_hint = "medium"
            actor = UnifiedActor(user=get_val("TargetUserName") or get_val("SubjectUserName") or None)

        elif event_id == "1102": # Audit Log Cleared
            category = "system"
            action = "audit_log_cleared"
            severity_hint = "critical"
            actor = UnifiedActor(user=get_val("SubjectUserName") or None, elevated=True)

        # Active Directory & Kerberos Events (Windows Server)
        elif event_id == "4768":
            category = "auth"
            action = "kerberos_tgt_request"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)
            ip = get_val("IpAddress")
            network = UnifiedNetwork(src_ip=ip if ip and ip != "-" else None)

        elif event_id == "4769":
            category = "auth"
            action = "kerberos_tgs_request"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)

        elif event_id == "4771":
            category = "auth"
            action = "kerberos_preauth_failed"
            outcome = "failure"
            severity_hint = "medium"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)

        elif event_id == "4776":
            category = "auth"
            action = "ntlm_authentication"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)

        elif event_id == "4740":
            category = "auth"
            action = "account_lockout"
            outcome = "failure"
            severity_hint = "high"
            actor = UnifiedActor(user=get_val("TargetUserName") or None)

    # -------------------------------------------------------------
    # 3. POWERSHELL SCRIPT BLOCK LOGGING
    # -------------------------------------------------------------
    elif "powershell" in channel.lower():
        category = "process"
        action = "powershell_script_block"
        severity_hint = "medium"
        script_text = get_val("ScriptBlockText")
        process = UnifiedProcess(
            name="powershell.exe",
            command_line=script_text or None
        )
        actor = UnifiedActor(user=get_val("UserId") or None)

    # -------------------------------------------------------------
    # 4. RDP & TERMINAL SERVICES (Windows Server)
    # -------------------------------------------------------------
    elif "terminalsrvices" in channel.lower() or "terminalsrv" in channel.lower() or "localsessionmanager" in channel.lower() or "remoteconnectionmanager" in channel.lower():
        category = "auth"
        action = "rdp_session_connect"
        ip = get_val("Address") or get_val("ClientIP")
        user = get_val("User")
        network = UnifiedNetwork(src_ip=ip if ip and ip != "-" else None, protocol="tcp", dst_port=3389)
        actor = UnifiedActor(user=user or None)

    # -------------------------------------------------------------
    # 5. FIREWALL & SYSTEM
    # -------------------------------------------------------------
    elif "firewall" in channel.lower():
        category = "network"
        action = "firewall_block" if "drop" in str(payload).lower() else "firewall_allow"
        outcome = "blocked" if action == "firewall_block" else "success"
        network = UnifiedNetwork(
            src_ip=get_val("SourceIP") or None,
            dst_ip=get_val("DestinationIP") or None,
            protocol=get_val("Protocol").lower() or "tcp"
        )

    return category, action, outcome, severity_hint, actor, process, network, file_or_reg
