#!/bin/bash
set -uo pipefail
# Deep security audit — daily timer
# Drift detection, rootkit checks, crypto mining, kernel params

OUT="/var/lib/agent-monitor/spool/deep-audit.json"
BASELINE_DIR="/var/lib/agent-monitor/cache"
FINDINGS_FILE=$(mktemp)
NOW=$(date +%s)

# Initialize empty findings array
echo "[]" > "$FINDINGS_FILE"

add() {
    local cat="$1" sev="$2" desc="$3"
    python3 -c "
import json
with open('$FINDINGS_FILE') as f:
    findings = json.load(f)
findings.append({'category': '$cat', 'severity': '$sev', 'description': $(python3 -c "import json; print(json.dumps('$desc'))"), 'ts': $NOW})
with open('$FINDINGS_FILE', 'w') as f:
    json.dump(findings, f)
"
}

# --- SUID/SGID binary drift ---
SUID_CURRENT="$BASELINE_DIR/suid-current.txt"
SUID_BASELINE="$BASELINE_DIR/suid-baseline.txt"
find /usr /bin /sbin -perm -4000 -o -perm -2000 2>/dev/null | sort > "$SUID_CURRENT"
if [ -f "$SUID_BASELINE" ]; then
    NEW_SUID=$(comm -13 "$SUID_BASELINE" "$SUID_CURRENT" | tr '\n' ' ')
    [ -n "$NEW_SUID" ] && add "suid_drift" "high" "New SUID/SGID binaries: $NEW_SUID"
fi
cp "$SUID_CURRENT" "$SUID_BASELINE"

# --- Hidden processes ---
HIDDEN=0
for pid in /proc/[0-9]*; do
    p=$(basename "$pid")
    ps -p "$p" >/dev/null 2>&1 || HIDDEN=$((HIDDEN + 1))
done
[ "$HIDDEN" -gt 0 ] && add "hidden_process" "critical" "$HIDDEN hidden processes in /proc"

# --- UID 0 accounts ---
UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | tr '\n' ' ')
[ -n "$UID0" ] && add "uid0_accounts" "critical" "Non-root UID 0: $UID0"

# --- Suspicious cron ---
SUSP_CRON=0
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -qiE "curl|wget|python.*http|/dev/tcp|nc -" && SUSP_CRON=$((SUSP_CRON + 1))
done
[ "$SUSP_CRON" -gt 0 ] && add "suspicious_cron" "high" "$SUSP_CRON users with suspicious cron entries"

# --- Crypto mining ---
MINING_CPU=$(ps aux | awk '$3 > 80 {print $11}' | grep -ciE "xmrig|minerd|ccminer|xmr-stak|minergate" || true)
MINING_NET=$(ss -tnp 2>/dev/null | grep -cE ":3333|:4444|:5555|:8333" || true)
[ "$MINING_CPU" -gt 0 ] && add "crypto_mining" "critical" "Mining process detected"
[ "$MINING_NET" -gt 0 ] && add "crypto_mining" "critical" "Mining pool connection detected"

# --- Kernel security params ---
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ] && add "kernel" "medium" "IP forwarding enabled"
[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" != "1" ] && add "kernel" "medium" "SYN cookies disabled"
[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" != "2" ] && add "kernel" "medium" "ASLR not fully enabled"

# --- World-writable in /etc ---
WW=$(find /etc -perm -o+w -type f 2>/dev/null | wc -l)
[ "$WW" -gt 0 ] && add "world_writable" "high" "$WW world-writable files in /etc"

# --- Deleted files still open ---
DELETED_OPEN=$(lsof 2>/dev/null | grep -c "deleted" || echo "0")
[ "$DELETED_OPEN" -gt 10 ] && add "deleted_open" "medium" "$DELETED_OPEN deleted files held open"

# --- Listening port drift ---
PORTS_CURRENT="$BASELINE_DIR/ports-current.txt"
PORTS_BASELINE="$BASELINE_DIR/ports-baseline.txt"
ss -tlnp | awk 'NR>1 {print $4}' | sort > "$PORTS_CURRENT"
if [ -f "$PORTS_BASELINE" ]; then
    NEW_PORTS=$(comm -13 "$PORTS_BASELINE" "$PORTS_CURRENT" | tr '\n' ' ')
    [ -n "$NEW_PORTS" ] && add "port_drift" "high" "New listening ports: $NEW_PORTS"
fi
cp "$PORTS_CURRENT" "$PORTS_BASELINE"

# --- Raw sockets ---
RAW_SOCKETS=$(lsof 2>/dev/null | grep -cE "raw|packet" || echo "0")
[ "$RAW_SOCKETS" -gt 2 ] && add "raw_sockets" "medium" "$RAW_SOCKETS raw/packet sockets"

# --- Capabilities ---
CAP_BINS=$(getcap -r /usr /bin /sbin 2>/dev/null | wc -l)

# --- Build output ---
SUID_COUNT=$(wc -l < "$SUID_CURRENT")

python3 -c "
import json
with open('$FINDINGS_FILE') as f:
    findings = json.load(f)
total = len(findings)
crit = sum(1 for f in findings if f['severity'] == 'critical')
high = sum(1 for f in findings if f['severity'] == 'high')

result = {
    'service': 'deep-audit',
    'findings_count': total,
    'critical': crit,
    'high': high,
    'suid_count': $SUID_COUNT,
    'deleted_open': $DELETED_OPEN,
    'raw_sockets': $RAW_SOCKETS,
    'cap_binaries': $CAP_BINS,
    'findings': findings,
    'ts': $NOW
}
with open('$OUT', 'w') as f:
    json.dump(result, f, indent=2)

# Prometheus
with open('/var/lib/node_exporter/textfile_collector/deep-audit.prom', 'w') as f:
    f.write('# HELP kvm4_audit_findings_total Deep audit findings\n')
    f.write('# TYPE kvm4_audit_findings_total gauge\n')
    f.write(f'kvm4_audit_findings_total {total}\n')
    f.write('# HELP kvm4_audit_critical Critical findings\n')
    f.write('# TYPE kvm4_audit_critical gauge\n')
    f.write(f'kvm4_audit_critical {crit}\n')
    f.write('# HELP kvm4_audit_suid_count SUID binary count\n')
    f.write('# TYPE kvm4_audit_suid_count gauge\n')
    f.write(f'kvm4_audit_suid_count {$SUID_COUNT}\n')
    f.write('# HELP kvm4_audit_deleted_open Deleted files held open\n')
    f.write('# TYPE kvm4_audit_deleted_open gauge\n')
    f.write(f'kvm4_audit_deleted_open {$DELETED_OPEN}\n')
    f.write('# HELP kvm4_audit_raw_sockets Raw sockets open\n')
    f.write('# TYPE kvm4_audit_raw_sockets gauge\n')
    f.write(f'kvm4_audit_raw_sockets {$RAW_SOCKETS}\n')
"

rm -f "$FINDINGS_FILE"
