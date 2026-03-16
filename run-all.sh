#!/bin/bash
set -euo pipefail
# Agent Monitor — run all plugins and local checks
# Called by systemd timer every 5 minutes

LOG="/var/lib/agent-monitor/state/last-run.json"
START=$(date +%s)
ERRORS=0

# Run all plugins
for script in /opt/agent-monitor/plugins/*.sh; do
  [ -x "$script" ] || continue
  NAME=$(basename "$script" .sh)
  if ! timeout 30 "$script" 2>/dev/null; then
    ERRORS=$((ERRORS + 1))
    echo "[agent-monitor] plugin failed: $NAME" >&2
  fi
done

# Run all local checks
for script in /opt/agent-monitor/local/*.sh; do
  [ -x "$script" ] || continue
  NAME=$(basename "$script" .sh)
  if ! timeout 15 "$script" 2>/dev/null; then
    ERRORS=$((ERRORS + 1))
    echo "[agent-monitor] local check failed: $NAME" >&2
  fi
done

END=$(date +%s)
DURATION=$((END - START))

cat > "$LOG" << JSONEOF
{
  "last_run": $END,
  "duration_sec": $DURATION,
  "errors": $ERRORS,
  "plugins": $(ls /opt/agent-monitor/plugins/*.sh 2>/dev/null | wc -l),
  "local_checks": $(ls /opt/agent-monitor/local/*.sh 2>/dev/null | wc -l)
}
JSONEOF

# Run extensions
for script in /opt/agent-monitor/extensions/*.sh; do
  [ -x "$script" ] || continue
  NAME=$(basename "$script" .sh)
  if ! timeout 30 "$script" 2>/dev/null; then
    ERRORS=$((ERRORS + 1))
    echo "[agent-monitor] extension failed: $NAME" >&2
  fi
done
