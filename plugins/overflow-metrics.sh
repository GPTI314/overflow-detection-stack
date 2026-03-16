#!/bin/bash
set -euo pipefail
# System metrics collector for Prometheus/Grafana
# Combines ps/ss/du for reliable metrics + sysdig for overflow detection
# Runs every 5 minutes via systemd timer

OUT="/var/lib/node_exporter/textfile_collector/sysdig.prom"
TMP="${OUT}.tmp"

cat > "$TMP" << 'HEADER'
# HELP kvm4_top_process_cpu Top 5 processes by CPU percent
# TYPE kvm4_top_process_cpu gauge
# HELP kvm4_top_process_mem Top 5 processes by memory percent
# TYPE kvm4_top_process_mem gauge
# HELP kvm4_varlog_size_bytes Total /var/log size in bytes
# TYPE kvm4_varlog_size_bytes gauge
# HELP kvm4_varlog_growth_bytes /var/log growth in 3-second sample window
# TYPE kvm4_varlog_growth_bytes gauge
# HELP kvm4_journal_size_bytes Systemd journal size in bytes
# TYPE kvm4_journal_size_bytes gauge
# HELP kvm4_open_connections Number of established TCP connections
# TYPE kvm4_open_connections gauge
# HELP kvm4_docker_containers Docker container count by state
# TYPE kvm4_docker_containers gauge
# HELP kvm4_wg_peer_handshake_age_seconds WireGuard peer last handshake age
# TYPE kvm4_wg_peer_handshake_age_seconds gauge
# HELP kvm4_sysdig_varlog_writes Write syscalls to /var/log in 3-second window
# TYPE kvm4_sysdig_varlog_writes gauge
# HELP kvm4_collection_timestamp_seconds Time of last collection
# TYPE kvm4_collection_timestamp_seconds gauge
HEADER

# 1. Top 5 processes by CPU
ps aux --sort=-%cpu | head -6 | tail -5 | awk '{
    proc=$11; gsub(/.*\//, "", proc); gsub(/"/, "", proc);
    if (length(proc) > 30) proc=substr(proc, 1, 30);
    printf "kvm4_top_process_cpu{process=\"%s\",pid=\"%s\"} %s\n", proc, $2, $3
}' >> "$TMP"

# 2. Top 5 processes by memory
ps aux --sort=-%mem | head -6 | tail -5 | awk '{
    proc=$11; gsub(/.*\//, "", proc); gsub(/"/, "", proc);
    if (length(proc) > 30) proc=substr(proc, 1, 30);
    printf "kvm4_top_process_mem{process=\"%s\",pid=\"%s\"} %s\n", proc, $2, $3
}' >> "$TMP"

# 3. /var/log size + growth detection
VARLOG_SIZE=$(du -sb /var/log 2>/dev/null | awk '{print $1}')
echo "kvm4_varlog_size_bytes ${VARLOG_SIZE:-0}" >> "$TMP"

# Measure growth over 3 seconds (overflow detector)
sleep 3
VARLOG_SIZE2=$(du -sb /var/log 2>/dev/null | awk '{print $1}')
GROWTH=$(( ${VARLOG_SIZE2:-0} - ${VARLOG_SIZE:-0} ))
echo "kvm4_varlog_growth_bytes ${GROWTH}" >> "$TMP"

# 4. Journal size
JOURNAL_BYTES=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.\d+[MGK]' | head -1)
# Convert to bytes
JOURNAL_SIZE=0
if echo "$JOURNAL_BYTES" | grep -q "G"; then
    JOURNAL_SIZE=$(echo "$JOURNAL_BYTES" | sed 's/G//' | awk '{printf "%.0f", $1 * 1073741824}')
elif echo "$JOURNAL_BYTES" | grep -q "M"; then
    JOURNAL_SIZE=$(echo "$JOURNAL_BYTES" | sed 's/M//' | awk '{printf "%.0f", $1 * 1048576}')
elif echo "$JOURNAL_BYTES" | grep -q "K"; then
    JOURNAL_SIZE=$(echo "$JOURNAL_BYTES" | sed 's/K//' | awk '{printf "%.0f", $1 * 1024}')
fi
echo "kvm4_journal_size_bytes ${JOURNAL_SIZE}" >> "$TMP"

# 5. TCP connections count
CONNS=$(ss -tn state established | tail -n +2 | wc -l)
echo "kvm4_open_connections ${CONNS}" >> "$TMP"

# 6. Docker containers by state
RUNNING=$(docker ps -q 2>/dev/null | wc -l)
STOPPED=$(docker ps -aq --filter "status=exited" 2>/dev/null | wc -l)
echo "kvm4_docker_containers{state=\"running\"} ${RUNNING}" >> "$TMP"
echo "kvm4_docker_containers{state=\"stopped\"} ${STOPPED}" >> "$TMP"

# 7. WireGuard peer handshake ages
NOW=$(date +%s)
wg show wg0 latest-handshakes 2>/dev/null | while read -r key ts; do
    AGE=$(( NOW - ts ))
    SHORT="${key:0:8}"
    echo "kvm4_wg_peer_handshake_age_seconds{peer=\"${SHORT}\"} ${AGE}"
done >> "$TMP"

# 8. sysdig: /var/log write syscalls (the overflow canary)
if command -v sysdig &>/dev/null; then
    WRITES=$(timeout 3 sysdig -c "evt.count" "evt.type=write and fd.name contains /var/log" 2>/dev/null | grep -oP '^\d+' || echo "0")
    echo "kvm4_sysdig_varlog_writes ${WRITES:-0}" >> "$TMP"
else
    echo "kvm4_sysdig_varlog_writes 0" >> "$TMP"
fi

# Timestamp
echo "kvm4_collection_timestamp_seconds $(date +%s)" >> "$TMP"

# Atomic move
mv "$TMP" "$OUT"
