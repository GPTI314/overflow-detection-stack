#!/bin/bash
set -euo pipefail
OUT="/var/lib/agent-monitor/spool/security.json"

# Listening ports
LISTENING=$(ss -tuln | grep -c LISTEN || echo "0")

# SUID binaries (limit to common dirs, not full filesystem)
SUID_COUNT=$(find /usr /bin /sbin -perm -4000 2>/dev/null | wc -l)

# SSH config
SSH_ROOT=$(grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "unknown")
SSH_PASSWD=$(grep -E '^\s*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "unknown")

# Failed auth (last hour)
FAILED_AUTH=$(grep -c "Failed\|Invalid user" /var/log/auth.log 2>/dev/null || echo "0")

# World-writable in /etc only (fast)
WORLD_WRITABLE=$(find /etc -perm -o+w -type f 2>/dev/null | wc -l)

# Zombies
ZOMBIES=$(ps aux | awk '$8 ~ /Z/ {count++} END {print count+0}')

# Active users
ACTIVE_USERS=$(who | wc -l)

cat > "$OUT" << JSONEOF
{
  "service": "security-audit",
  "listening_ports": $LISTENING,
  "suid_binaries": $SUID_COUNT,
  "ssh_permit_root": "$SSH_ROOT",
  "ssh_password_auth": "$SSH_PASSWD",
  "failed_auth_today": $FAILED_AUTH,
  "world_writable_etc": $WORLD_WRITABLE,
  "zombie_processes": $ZOMBIES,
  "active_users": $ACTIVE_USERS,
  "ts": $(date +%s)
}
JSONEOF
