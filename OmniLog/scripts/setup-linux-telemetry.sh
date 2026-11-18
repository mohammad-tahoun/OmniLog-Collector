#!/usr/bin/env bash
# ==============================================================================
# Force-Fields Linux Telemetry Setup Script
# Configures high-fidelity auditd rules, journald, and permissions for Force-Fields SOC.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}   FORCE-FIELDS SOC: LINUX TELEMETRY & AUDITD SETUP       ${NC}"
echo -e "${CYAN}==========================================================${NC}"

# 1. Verify Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Error: This script must be executed as root (sudo bash setup-linux-telemetry.sh)${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Elevated root privileges confirmed.${NC}"

# 2. Install auditd and audispd if not present
echo -e "${YELLOW}[+] Verifying auditd installation...${NC}"
if ! command -v auditctl &> /dev/null; then
    echo -e "${YELLOW}[*] Installing auditd package...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y auditd audispd-plugins
    elif command -v dnf &> /dev/null; then
        dnf install -y audit audit-libs
    elif command -v yum &> /dev/null; then
        yum install -y audit
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm audit
    elif command -v zypper &> /dev/null; then
        zypper install -y audit
    else
        echo -e "${RED}[-] Could not detect package manager. Please install auditd manually.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[+] auditd binary verified.${NC}"

# 3. Create Force-Fields Comprehensive Audit Rules
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/forcefields.rules"
mkdir -p "$RULES_DIR"

echo -e "${YELLOW}[+] Deploying high-fidelity audit rules to ${RULES_FILE}...${NC}"

cat << 'EOF' > "$RULES_FILE"
# ------------------------------------------------------------------------------
# Force-Fields AI-SOC Comprehensive Audit Rules
# ------------------------------------------------------------------------------

# Remove all existing rules
-D

# Buffer size (8192 records)
-b 8192

# Failure mode (1 = print failure warnings)
-f 1

# Rate limit (0 = unlimited)
-r 0

# ------------------------------------------------------------------------------
# 1. Process Executions (execve / execveat for 64-bit and 32-bit)
# ------------------------------------------------------------------------------
-a always,exit -F arch=b64 -S execve,execveat -k process_exec
-a always,exit -F arch=b32 -S execve,execveat -k process_exec

# ------------------------------------------------------------------------------
# 2. Identity and Credentials Watching
# ------------------------------------------------------------------------------
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/pam.d/ -p wa -k identity

# ------------------------------------------------------------------------------
# 3. Privilege Escalation & Sudoers
# ------------------------------------------------------------------------------
-w /etc/sudoers -p wa -k priv_escalation
-w /etc/sudoers.d/ -p wa -k priv_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config

# ------------------------------------------------------------------------------
# 4. Privilege Changes (setuid, setgid)
# ------------------------------------------------------------------------------
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k priv_change
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -k priv_change

# ------------------------------------------------------------------------------
# 5. Critical Binary Modification
# ------------------------------------------------------------------------------
-w /bin/ -p wa -k bin_mods
-w /sbin/ -p wa -k bin_mods
-w /usr/bin/ -p wa -k bin_mods
-w /usr/sbin/ -p wa -k bin_mods

# ------------------------------------------------------------------------------
# 6. Kernel Module Alterations
# ------------------------------------------------------------------------------
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module,finit_module -k kernel_modules

# ------------------------------------------------------------------------------
# 7. Network Outbound Socket Connections
# ------------------------------------------------------------------------------
-a always,exit -F arch=b64 -S connect -k network_connect

# ------------------------------------------------------------------------------
# 8. Cron and Scheduled Tasks
# ------------------------------------------------------------------------------
-w /etc/cron.allow -p wa -k cron_mods
-w /etc/cron.deny -p wa -k cron_mods
-w /etc/cron.d/ -p wa -k cron_mods
-w /etc/cron.daily/ -p wa -k cron_mods
-w /etc/cron.hourly/ -p wa -k cron_mods
-w /etc/cron.monthly/ -p wa -k cron_mods
-w /etc/cron.weekly/ -p wa -k cron_mods
-w /etc/crontab -p wa -k cron_mods
-w /var/spool/cron/ -p wa -k cron_mods
EOF

# 4. Reload and activate rules
echo -e "${YELLOW}[+] Reloading auditd rules...${NC}"
if command -v augenrules &> /dev/null; then
    augenrules --load
else
    auditctl -R "$RULES_FILE"
fi

# Ensure auditd service is running and enabled
if command -v systemctl &> /dev/null; then
    systemctl restart auditd 2>/dev/null || service auditd restart
    systemctl enable auditd 2>/dev/null || true
else
    service auditd restart
fi

# 5. Verify Permissions for Log Reading
AUDIT_LOG="/var/log/audit/audit.log"
if [ -f "$AUDIT_LOG" ]; then
    chmod 644 "$AUDIT_LOG" 2>/dev/null || true
fi

echo -e "${GREEN}[+] Current loaded audit rules count: $(auditctl -l | wc -l)${NC}"

echo -e "${CYAN}==========================================================${NC}"
echo -e "${GREEN}[SUCCESS] Linux telemetry & auditd successfully configured!${NC}"
echo -e "${CYAN}==========================================================${NC}"
EOF
