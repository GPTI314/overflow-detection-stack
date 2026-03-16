#!/bin/bash
set -uo pipefail
# NOTE: no -e — grep returning 1 (no match) is expected, not an error
# MITRE ATT&CK detection for Linux — maps suspicious activity to technique IDs
# Scans recent process activity and file access patterns
# Runs as agent-monitor extension

OUT="/var/lib/agent-monitor/spool/mitre-detect.json"
WINDOW=300  # 5 minute lookback

NOW=$(date +%s)
SINCE=$(date -d "@$((NOW - WINDOW))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u '+%Y-%m-%d %H:%M:%S')

FINDINGS="[]"

add_finding() {
    local technique="$1" tactic="$2" desc="$3" severity="$4"
    FINDINGS=$(echo "$FINDINGS" | python3 -c "
import sys, json
f = json.load(sys.stdin)
f.append({'technique': '$technique', 'tactic': '$tactic', 'description': '''$desc''', 'severity': '$severity', 'ts': $NOW})
print(json.dumps(f))
")
}

# T1016 — Network discovery (ifconfig, ip, arp)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "ifconfig|ip addr|ip route|arp -a"; then
    add_finding "T1016" "Discovery" "Network config enumeration detected" "low"
fi

# T1033 — User discovery (who, users, w)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "\bwho\b|\busers\b|\bfinger\b"; then
    add_finding "T1033" "Discovery" "User enumeration utility detected" "low"
fi

# T1040 — Network sniffing (tcpdump)
if pgrep -x tcpdump >/dev/null 2>&1; then
    add_finding "T1040" "Discovery" "tcpdump actively capturing traffic" "medium"
fi

# T1105 — Ingress tool transfer (curl/wget to download)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "curl.*-o |curl.*--output|wget.*http"; then
    add_finding "T1105" "Command_Control" "File download via curl/wget detected" "medium"
fi

# T1069.002 — Group policy discovery
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "\bgroups\b|\bid\b.*-G"; then
    add_finding "T1069.002" "Discovery" "Group policy enumeration detected" "low"
fi

# T1082 — System info discovery
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "uname -a|cat /etc/os-release|hostnamectl|lsb_release"; then
    add_finding "T1082" "Discovery" "System information gathering detected" "low"
fi

# T1136 — Account creation (useradd, adduser)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "useradd|adduser"; then
    add_finding "T1136" "Persistence" "User account creation detected" "high"
fi

# T1574.006 — LD_PRELOAD hijacking
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "LD_PRELOAD"; then
    add_finding "T1574.006" "Hijack_Execution" "LD_PRELOAD usage detected — possible code injection" "critical"
fi

# T1053.003 — Cron persistence
CRON_CHANGES=$(find /var/spool/cron /etc/cron.d /etc/crontab -newer /var/lib/agent-monitor/state/last-run.json 2>/dev/null | wc -l)
if [ "$CRON_CHANGES" -gt 0 ]; then
    add_finding "T1053.003" "Persistence" "Cron job modification detected" "high"
fi

# T1055.001 — ld.so.preload access
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "/etc/ld.so.preload"; then
    add_finding "T1055.001" "Defense_Evasion" "Access to /etc/ld.so.preload detected" "critical"
fi

# T1105 — wget to /tmp
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "wget.*/tmp/"; then
    add_finding "T1105" "Command_Control" "wget download to /tmp detected" "high"
fi

# T1003.008 — Credential access (/etc/shadow, /etc/gshadow)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "cat.*/etc/shadow|cat.*/etc/gshadow"; then
    add_finding "T1003.008" "Credential_Access" "OS credential file access detected" "critical"
fi

# T1552.003 — Bash history access
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "\.bash_history|\.history"; then
    add_finding "T1552.003" "Credential_Access" "Bash history access detected" "medium"
fi

# T1156.004 — Profile modification
PROFILE_CHANGES=$(find /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile 2>/dev/null -newer /var/lib/agent-monitor/state/last-run.json 2>/dev/null | wc -l)
if [ "$PROFILE_CHANGES" -gt 0 ]; then
    add_finding "T1546.004" "Persistence" "Shell profile modification detected" "high"
fi

# T1543.002 — Systemd service creation/modification
SYSTEMD_CHANGES=$(find /etc/systemd/system -newer /var/lib/agent-monitor/state/last-run.json -name '*.service' 2>/dev/null | wc -l)
if [ "$SYSTEMD_CHANGES" -gt 0 ]; then
    add_finding "T1543.002" "Persistence" "Systemd service creation/modification detected" "high"
fi

# T1485 — Data destruction (rm -rf)
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "rm -rf|rm -r /"; then
    add_finding "T1485" "Impact" "Recursive deletion detected" "critical"
fi

# T1087.001 — /etc/passwd access
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "cat.*/etc/passwd"; then
    add_finding "T1087.001" "Discovery" "Password file enumeration detected" "medium"
fi

# T1548.003 — Sudoers access
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "/etc/sudoers|visudo"; then
    add_finding "T1548.003" "Privilege_Escalation" "Sudoers file access detected" "high"
fi

# T1053.003 — Crontab utility usage
if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -qE "crontab -[elr]"; then
    add_finding "T1053.003" "Execution" "Crontab utility usage detected" "medium"
fi

# Count findings by severity
FINDING_COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
CRIT_COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(sum(1 for f in json.load(sys.stdin) if f['severity']=='critical'))")
HIGH_COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(sum(1 for f in json.load(sys.stdin) if f['severity']=='high'))")

cat > "$OUT" << JSONEOF
{
  "service": "mitre-detect",
  "window_sec": $WINDOW,
  "findings_count": $FINDING_COUNT,
  "critical": $CRIT_COUNT,
  "high": $HIGH_COUNT,
  "findings": $FINDINGS,
  "ts": $NOW
}
JSONEOF

# Prometheus metrics
PROM="/var/lib/node_exporter/textfile_collector/mitre.prom"
cat > "${PROM}.tmp" << PROMEOF
# HELP kvm4_mitre_findings_total MITRE ATT&CK detections in last window
# TYPE kvm4_mitre_findings_total gauge
kvm4_mitre_findings_total $FINDING_COUNT
# HELP kvm4_mitre_critical Critical MITRE detections
# TYPE kvm4_mitre_critical gauge
kvm4_mitre_critical $CRIT_COUNT
# HELP kvm4_mitre_high High MITRE detections
# TYPE kvm4_mitre_high gauge
kvm4_mitre_high $HIGH_COUNT
PROMEOF
mv "${PROM}.tmp" "$PROM"
