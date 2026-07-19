#!/usr/bin/env bash
# =============================================================================
# scml - middleware layer secure | Exhibition Start Script
# Usage: bash start.sh
# Starts: TrustMediator stack + frontend server + AI agent orchestrator
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[start]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }
step() { echo -e "\n${CYAN}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
LOG_DIR="$SCRIPT_DIR/.logs"
mkdir -p "$LOG_DIR"

# ── Step 1: Free ports ────────────────────────────────────────────
step "Step 1 — Freeing ports 3000 & 3001"

for PORT in 3000 3001; do
  PID=$(lsof -t -i:$PORT 2>/dev/null || true)
  if [[ -n "$PID" ]]; then
    kill -9 $PID && log "Killed process on port $PORT (PID $PID)"
  else
    log "Port $PORT already free"
  fi
done

# ── Step 2: Check TrustMediator stack ────────────────────────────
step "Step 2 — Checking TrustMediator backend"

if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
  log "TrustMediator is already running ✓"
else
  warn "TrustMediator is not running — starting with Docker..."
  if command -v docker &>/dev/null; then
    sudo docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
    log "Waiting for health check..."
    ELAPSED=0
    until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
      if [[ $ELAPSED -ge 60 ]]; then
        err "TrustMediator did not start in 60s. Run: sudo bash deploy.sh"
      fi
      sleep 3; ELAPSED=$((ELAPSED+3))
    done
    log "TrustMediator is healthy ✓"
  else
    err "Docker not found. Run: sudo bash deploy.sh first"
  fi
fi

# ── Step 3: Start frontend server ────────────────────────────────
step "Step 3 — Starting frontend server on :3000"

python3 -m http.server 3000 --directory "$FRONTEND_DIR" \
  > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
sleep 1

if kill -0 $FRONTEND_PID 2>/dev/null; then
  log "Frontend server started (PID $FRONTEND_PID) → http://localhost:3000"
else
  err "Frontend server failed to start. Check $LOG_DIR/frontend.log"
fi

# ── Step 4: Start orchestrator ────────────────────────────────────
step "Step 4 — Starting AI Agent Orchestrator on :3001"

python3 "$SCRIPT_DIR/orchestrator.py" --loop --delay 4 \
  > "$LOG_DIR/orchestrator.log" 2>&1 &
ORCH_PID=$!
sleep 2

if kill -0 $ORCH_PID 2>/dev/null; then
  log "Orchestrator started (PID $ORCH_PID) → SSE on http://localhost:3001/events"
else
  err "Orchestrator failed. Check $LOG_DIR/orchestrator.log"
fi

# ── Step 5: Save PIDs for stop script ────────────────────────────
echo "$FRONTEND_PID" > "$LOG_DIR/frontend.pid"
echo "$ORCH_PID"     > "$LOG_DIR/orchestrator.pid"

# ── Step 6: Open browser ──────────────────────────────────────────
step "Step 6 — Opening browser"
sleep 1
xdg-open "http://localhost:3000/demo.html" 2>/dev/null || \
  log "Open manually: http://localhost:3000/demo.html"

# ── Summary ───────────────────────────────────────────────────────
step "All Systems Live"
echo ""
echo -e "${GREEN}  ✔ TrustMediator API:${NC}    ${CYAN}http://localhost:8000${NC}"
echo -e "${GREEN}  ✔ API Docs:${NC}             ${CYAN}http://localhost:8000/docs${NC}"
echo -e "${GREEN}  ✔ Live Agent Demo:${NC}      ${CYAN}http://localhost:3000/demo.html${NC}"
echo -e "${GREEN}  ✔ Dashboard:${NC}            ${CYAN}http://localhost:3000/index.html${NC}"
echo -e "${GREEN}  ✔ SSE Stream:${NC}           ${CYAN}http://localhost:3001/events${NC}"
echo ""
echo -e "  Logs:"
echo "    Frontend:     $LOG_DIR/frontend.log"
echo "    Orchestrator: $LOG_DIR/orchestrator.log"
echo ""
echo -e "${YELLOW}  To stop everything:   bash stop.sh${NC}"
echo ""
