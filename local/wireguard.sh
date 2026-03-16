#!/bin/bash
set -euo pipefail
OUT="/var/lib/agent-monitor/spool/wireguard.json"
NOW=$(date +%s)

PEERS="["
FIRST=true
while read -r key ts; do
  AGE=$((NOW - ts))
  SHORT="${key:0:12}"
  STALE="false"
  [ "$AGE" -gt 300 ] && STALE="true"
  $FIRST || PEERS="$PEERS,"
  PEERS="$PEERS{\"key\":\"$SHORT\",\"age_sec\":$AGE,\"stale\":$STALE}"
  FIRST=false
done < <(wg show wg0 latest-handshakes 2>/dev/null)
PEERS="$PEERS]"

cat > "$OUT" << JSONEOF
{
  "service": "wireguard",
  "interface": "wg0",
  "peers": $PEERS,
  "ts": $NOW
}
JSONEOF
