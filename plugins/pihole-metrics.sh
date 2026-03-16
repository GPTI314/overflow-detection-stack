#!/bin/bash
set -uo pipefail
# Pi-hole metrics for Prometheus via node_exporter textfile collector

OUT="/var/lib/node_exporter/textfile_collector/pihole.prom"
TMP="${OUT}.tmp"
PIHOLE_API="http://127.0.0.1:8053/api"
PIHOLE_PW="pihole-kvm4"

# Authenticate
SID=$(curl -s -X POST "${PIHOLE_API}/auth" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${PIHOLE_PW}\"}" 2>/dev/null | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('session',{}).get('sid',''))" 2>/dev/null)

if [ -z "$SID" ]; then
    echo "# pihole auth failed" > "$TMP"
    mv "$TMP" "$OUT"
    exit 0
fi

# Get stats
STATS=$(curl -s "${PIHOLE_API}/stats/summary" -H "sid: $SID" 2>/dev/null)

if [ -z "$STATS" ]; then
    echo "# pihole stats unavailable" > "$TMP"
    mv "$TMP" "$OUT"
    exit 0
fi

# Parse and write Prometheus metrics
python3 -c "
import json, sys

data = json.loads('''${STATS}''')
q = data.get('queries', {})
gravity = data.get('gravity', {})

lines = [
    '# HELP kvm4_pihole_queries_total Total DNS queries',
    '# TYPE kvm4_pihole_queries_total gauge',
    f'kvm4_pihole_queries_total {q.get(\"total\", 0)}',
    '# HELP kvm4_pihole_queries_blocked Blocked DNS queries',
    '# TYPE kvm4_pihole_queries_blocked gauge',
    f'kvm4_pihole_queries_blocked {q.get(\"blocked\", 0)}',
    '# HELP kvm4_pihole_percent_blocked Percentage of queries blocked',
    '# TYPE kvm4_pihole_percent_blocked gauge',
    f'kvm4_pihole_percent_blocked {q.get(\"percent_blocked\", 0):.2f}',
    '# HELP kvm4_pihole_unique_domains Unique domains seen',
    '# TYPE kvm4_pihole_unique_domains gauge',
    f'kvm4_pihole_unique_domains {q.get(\"unique_domains\", 0)}',
    '# HELP kvm4_pihole_forwarded Queries forwarded to upstream',
    '# TYPE kvm4_pihole_forwarded gauge',
    f'kvm4_pihole_forwarded {q.get(\"forwarded\", 0)}',
    '# HELP kvm4_pihole_cached Queries answered from cache',
    '# TYPE kvm4_pihole_cached gauge',
    f'kvm4_pihole_cached {q.get(\"cached\", 0)}',
    '# HELP kvm4_pihole_gravity_domains Domains in blocklist',
    '# TYPE kvm4_pihole_gravity_domains gauge',
    f'kvm4_pihole_gravity_domains {gravity.get(\"domains_being_blocked\", 0)}',
]

# Query types
for qtype, count in q.get('types', {}).items():
    if count > 0:
        lines.append(f'kvm4_pihole_query_type{{type=\"{qtype}\"}} {count}')

print('\\n'.join(lines))
" > "$TMP" 2>/dev/null

mv "$TMP" "$OUT"
