#!/bin/bash
# Local check: sovereign-docs health
set -euo pipefail
OUT="/var/lib/agent-monitor/spool/sovereign-docs.json"

STATUS=$(systemctl is-active sovereign-docs 2>/dev/null || echo "inactive")
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8486/api/pages 2>/dev/null || echo "000")
PAGE_COUNT=$(sqlite3 ~/.automagpt/sovereign/pages.sqlite "SELECT COUNT(*) FROM pages WHERE deleted_at IS NULL;" 2>/dev/null || echo "0")
BUILD_COUNT=$(sqlite3 ~/.automagpt/sovereign/pages.sqlite "SELECT COUNT(*) FROM codespace_builds;" 2>/dev/null || echo "0")
THREAD_COUNT=$(sqlite3 ~/.automagpt/sovereign/pages.sqlite "SELECT COUNT(*) FROM threads;" 2>/dev/null || echo "0")
WAL_SIZE=$(stat -c%s ~/.automagpt/sovereign/pages.sqlite-wal 2>/dev/null || echo "0")

cat > "$OUT" << JSONEOF
{
  "service": "sovereign-docs",
  "status": "$STATUS",
  "http_code": $HTTP,
  "pages": $PAGE_COUNT,
  "builds": $BUILD_COUNT,
  "threads": $THREAD_COUNT,
  "wal_bytes": $WAL_SIZE,
  "ts": $(date +%s)
}
JSONEOF
