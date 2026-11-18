import os
from typing import Dict, Any, Tuple
from app.schemas import UnifiedActor, UnifiedProcess, UnifiedNetwork, UnifiedFileOrRegistry

def map_linux_event(
    channel: str,
    event_id: str,
    payload: Dict[str, Any]
) -> Tuple[str, str, str, str, UnifiedActor, UnifiedProcess, UnifiedNetwork, UnifiedFileOrRegistry]:
    """
    Maps Linux auditd, auth.log, syslog, and journald telemetry into Unified Schema components.
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

    event_type = payload.get("event_type", "")

    # -------------------------------------------------------------
    # 1. AUDITD PARSER (EXECVE, PROCTITLE, SYSCALL, SOCKADDR)
    # -------------------------------------------------------------
    if channel == "auditd":
        syscall_rec = payload.get("syscall", {})
        exe = syscall_rec.get("exe") or payload.get("proc_exe_path")
        pid_str = syscall_rec.get("pid") or payload.get("pid")
        ppid_str = syscall_rec.get("ppid") or payload.get("ppid")
        uid_str = syscall_rec.get("uid") or payload.get("uid")
        cmdline = payload.get("decoded_command_line") or ""
        sha256_hash = payload.get("proc_exe_sha256")

        pid = int(pid_str) if pid_str and str(pid_str).isdigit() else None
        ppid = int(ppid_str) if ppid_str and str(ppid_str).isdigit() else None
        uid = int(uid_str) if uid_str and str(uid_str).isdigit() else None

        category = "process"
        action = "process_created"
        outcome = "success" if syscall_rec.get("success") == "yes" else "failure"

        # Check for socket/network syscalls
        syscall_num = syscall_rec.get("syscall")
        if syscall_num in ["42", "43"]: # connect, accept on x86_64
            category = "network"
            action = "network_connect"

        # Check for critical file watch triggers
        key = syscall_rec.get("key", "").lower()
        if "identity" in key or "priv_escalation" in key or "bin_mods" in key:
            category = "file_or_registry"
            action = "file_modification"
            severity_hint = "high" if "shadow" in str(payload) else "medium"
            file_or_reg = UnifiedFileOrRegistry(
                target_path=payload.get("path", {}).get("name") or None,
                operation="write"
            )

        process = UnifiedProcess(
            pid=pid,
            ppid=ppid,
            name=os.path.basename(exe) if exe else None,
            executable=exe or None,
            command_line=cmdline or None,
            hash_sha256=sha256_hash or None
        )

        actor = UnifiedActor(
            user=f"uid:{uid}" if uid is not None else None,
            user_id=str(uid) if uid is not None else None,
            elevated=uid == 0
        )

    # -------------------------------------------------------------
    # 2. AUTH LOG (SSH, Sudo, Su, Cron)
    # -------------------------------------------------------------
    elif channel == "auth":
        if event_type == "ssh_login_success":
            category = "auth"
            action = "ssh_login_success"
            outcome = "success"
            severity_hint = "low"
            actor = UnifiedActor(user=payload.get("user") or None)
            network = UnifiedNetwork(
                protocol="tcp",
                src_ip=payload.get("src_ip") or None,
                src_port=int(payload.get("src_port")) if str(payload.get("src_port", "")).isdigit() else None,
                dst_port=22
            )

        elif event_type == "ssh_login_failure":
            category = "auth"
            action = "ssh_login_failure"
            outcome = "failure"
            severity_hint = "medium"
            actor = UnifiedActor(user=payload.get("user") or None)
            network = UnifiedNetwork(
                protocol="tcp",
                src_ip=payload.get("src_ip") or None,
                src_port=int(payload.get("src_port")) if str(payload.get("src_port", "")).isdigit() else None,
                dst_port=22
            )

        elif event_type == "sudo_execution":
            category = "process"
            action = "sudo_execution"
            outcome = "success"
            severity_hint = "medium"
            actor = UnifiedActor(
                user=payload.get("actor_user") or None,
                elevated=True
            )
            cmd = payload.get("command") or ""
            process = UnifiedProcess(
                name="sudo",
                command_line=cmd,
                executable="/usr/bin/sudo"
            )

    # -------------------------------------------------------------
    # 3. SYSLOG / FIREWALL (UFW / Iptables)
    # -------------------------------------------------------------
    elif channel == "syslog":
        if event_type == "firewall_block":
            category = "network"
            action = "firewall_block"
            outcome = "blocked"
            severity_hint = "medium"
            network = UnifiedNetwork(
                protocol=payload.get("protocol") or "tcp",
                src_ip=payload.get("src_ip") or None,
                dst_ip=payload.get("dst_ip") or None
            )

    # -------------------------------------------------------------
    # 4. JOURNALD
    # -------------------------------------------------------------
    elif channel == "journald":
        comm = payload.get("_COMM")
        pid_str = payload.get("_PID")
        msg = payload.get("MESSAGE")
        uid_str = payload.get("_UID")

        category = "system"
        action = "journald_entry"
        process = UnifiedProcess(
            name=comm or None,
            pid=int(pid_str) if pid_str and str(pid_str).isdigit() else None,
            command_line=str(msg)[:255] if msg else None
        )
        actor = UnifiedActor(
            user_id=str(uid_str) if uid_str else None,
            elevated=str(uid_str) == "0"
        )

    return category, action, outcome, severity_hint, actor, process, network, file_or_reg
