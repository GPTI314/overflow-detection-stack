#!/bin/bash
set -euo pipefail
OUT="/var/lib/agent-monitor/spool/docker.json"

RUNNING=$(docker ps -q 2>/dev/null | wc -l)
STOPPED=$(docker ps -aq --filter "status=exited" 2>/dev/null | wc -l)
UNHEALTHY=$(docker ps --filter "health=unhealthy" -q 2>/dev/null | wc -l)
RESTARTING=$(docker ps --filter "status=restarting" -q 2>/dev/null | wc -l)

# Top 3 by memory
TOP_MEM=$(docker stats --no-stream --format '{"name":"{{.Name}}","mem":"{{.MemUsage}}","cpu":"{{.CPUPerc}}"}' 2>/dev/null | head -3 | paste -sd,)

cat > "$OUT" << JSONEOF
{
  "service": "docker",
  "running": $RUNNING,
  "stopped": $STOPPED,
  "unhealthy": $UNHEALTHY,
  "restarting": $RESTARTING,
  "top_mem": [$TOP_MEM],
  "ts": $(date +%s)
}
JSONEOF
