#!/usr/bin/env bash
# =============================================================================
# scml - middleware layer secure | Stop Script
# Usage: bash stop.sh
# =============================================================================
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[stop]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/.logs"

echo -e "\n${YELLOW}━━━ Stopping all scml services ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Kill by saved PIDs
for SVC in frontend orchestrator; do
  PID_FILE="$LOG_DIR/$SVC.pid"
  if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      kill "$PID" && log "Stopped $SVC (PID $PID)"
    else
      warn "$SVC was not running"
    fi
    rm -f "$PID_FILE"
  fi
done

# Also sweep ports just in case
for PORT in 3000 3001; do
  PID=$(lsof -t -i:$PORT 2>/dev/null || true)
  if [[ -n "$PID" ]]; then
    kill -9 $PID && log "Force-killed port $PORT (PID $PID)"
  fi
done

log "All services stopped ✓"
echo ""
