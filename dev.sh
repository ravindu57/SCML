#!/usr/bin/env bash
# =============================================================================
# scml - middleware layer secure | Local Development Script
# Usage: bash dev.sh [up|down|logs|restart]
# Starts the full stack with hot-reload, debug logging, and exposed DB ports.
# =============================================================================

set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[dev]${NC} $*"; }
info() { echo -e "${CYAN}[dev]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CMD="${1:-up}"

case "$CMD" in
  up)
    log "Starting dev stack (hot-reload + debug mode)..."
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
    echo ""
    info "Services running:"
    docker compose ps
    echo ""
    info "API (hot-reload):  http://localhost:8000"
    info "Swagger UI:        http://localhost:8000/docs"
    info "Logs:              bash dev.sh logs"
    ;;
  down)
    log "Stopping dev stack..."
    docker compose -f docker-compose.yml -f docker-compose.dev.yml down --remove-orphans
    ;;
  logs)
    docker compose logs -f trust-mediator
    ;;
  restart)
    log "Restarting trust-mediator (code changes applied)..."
    docker compose -f docker-compose.yml -f docker-compose.dev.yml restart trust-mediator
    ;;
  *)
    echo "Usage: bash dev.sh [up|down|logs|restart]"
    exit 1
    ;;
esac
