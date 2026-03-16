#!/bin/bash
set -euo pipefail
OUT="/var/lib/node_exporter/textfile_collector/security.prom"
TMP="${OUT}.tmp"

cat > "$TMP" << 'HEADER'
# HELP kvm4_listening_ports Number of listening TCP/UDP ports
# TYPE kvm4_listening_ports gauge
# HELP kvm4_suid_binaries Count of SUID binaries on system
# TYPE kvm4_suid_binaries gauge
# HELP kvm4_failed_auth_1h Failed SSH auth attempts in last hour
# TYPE kvm4_failed_auth_1h gauge
# HELP kvm4_world_writable Count of world-writable files in /etc /usr
# TYPE kvm4_world_writable gauge
# HELP kvm4_zombie_processes Count of zombie processes
# TYPE kvm4_zombie_processes gauge
# HELP kvm4_iptables_rules Total iptables rules count
# TYPE kvm4_iptables_rules gauge
# HELP kvm4_active_users Currently logged in users
# TYPE kvm4_active_users gauge
HEADER

echo "kvm4_listening_ports $(ss -tuln | grep LISTEN | wc -l)" >> "$TMP"
echo "kvm4_suid_binaries $(find /usr /bin /sbin -perm -4000 2>/dev/null | wc -l)" >> "$TMP"
echo "kvm4_failed_auth_1h $(journalctl -u sshd --since '1 hour ago' --no-pager 2>/dev/null | grep -c 'Failed\|Invalid' || echo 0)" >> "$TMP"
echo "kvm4_world_writable $(find /etc -perm -o+w -type f 2>/dev/null | wc -l)" >> "$TMP"
echo "kvm4_zombie_processes $(ps aux | awk '$8 ~ /Z/ {count++} END {print count+0}')" >> "$TMP"
echo "kvm4_iptables_rules $(iptables -S 2>/dev/null | wc -l)" >> "$TMP"
echo "kvm4_active_users $(who | wc -l)" >> "$TMP"

mv "$TMP" "$OUT"
