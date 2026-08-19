#!/usr/bin/env bash
# =============================================================================
# SCML demo stack — mediator + dashboard + both agent systems, one command.
#
#   bash run-demo.sh          start everything and verify it
#   bash run-demo.sh --stop   shut down only what this script started
#
#   Fail-closed demonstration (agents stay up, mediator does not):
#   bash run-demo.sh --stop-mediator
#   bash run-demo.sh --start-mediator
#
# Run this in YOUR OWN terminal. Processes started here are detached with
# setsid so they survive the shell that launched them.
#
# Ports:
#   8000  SCML mediator (API + /docs)
#   3100  dashboard (audit trail, policy, traffic)
#   4000  demo-agent      — single agent, you type the injection
#   4100  orchestrator    — four agents, injection arrives in a fetched document
#
# Why one policy load for both agent systems:
#   PUT /v1/policy replaces the WHOLE document. demo-agent and orchestrator
#   each ship their own policy.json, so loading them one after the other would
#   leave only the second one's agents defined and silently deny-all the first.
#   This script merges them and loads once. That single-tenancy limit is a
#   known gap, documented in CLAUDE.md.
# =============================================================================
set -uo pipefail

G=$'\033[0;32m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; C=$'\033[0;36m'; W=$'\033[1m'; N=$'\033[0m'
log()  { echo -e "${G}  ✔${N} $*"; }
warn() { echo -e "${Y}  !${N} $*"; }
err()  { echo -e "${R}  ✖${N} $*" >&2; }
step() { echo -e "\n${C}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
RUN="$DIR/.demo"
mkdir -p "$RUN"

MEDIATOR_PORT=8000
DASH_PORT=3100
AGENT_PORT=4000
ORCH_PORT=4100

# ── Fail-closed demonstration ────────────────────────────────────────────────
# Stop and start ONLY the mediator, leaving the agent consoles running.
#
# `--stop` would take the agents down too, which just shows a dead website.
# The point of the demonstration is the opposite: the agent is alive and
# willing, and still cannot act, because it cannot obtain authorisation.
# Find the mediator by what it is running, not by a recorded pid.
#
# The pid file is unreliable here: processes are launched through `setsid`,
# which forks and lets the parent exit, so `$!` captures a pid that is already
# dead by the time anyone reads it. Matching the uvicorn command line is exact
# — it cannot select anything but this mediator — and it survives the process
# being restarted by any means.
mediator_pids() { pgrep -f "uvicorn trust_mediator.api.app:app" 2>/dev/null; }

if [[ "${1:-}" == "--stop-mediator" ]]; then
  pids=$(mediator_pids)
  if [[ -z "$pids" ]]; then
    warn "mediator was not running"
    exit 0
  fi
  kill $pids 2>/dev/null
  for _ in $(seq 1 20); do
    mediator_pids >/dev/null || break
    sleep 0.3
  done
  # Anything still holding on gets a firmer request.
  pids=$(mediator_pids) && [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null
  rm -f "$RUN/mediator.pid"
  echo -e "\n${R}  ✖ mediator stopped${N} — agents on :4000 and :4100 are still running."
  echo -e "    Run any task now: every action fails CLOSED.\n"
  exit 0
fi

if [[ "${1:-}" == "--start-mediator" ]]; then
  VENV="$DIR/.venv"
  [[ -x "$VENV/bin/uvicorn" ]] || VENV="$(cd "$DIR/../../.." && pwd)/.venv"
  setsid nohup env DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" \
      TRUST_MEDIATOR_API_KEYS="" \
      "$VENV/bin/uvicorn" trust_mediator.api.app:app --host 0.0.0.0 --port 8000 \
      > "$RUN/mediator.log" 2>&1 < /dev/null &
  for _ in $(seq 1 40); do
    curl -sf "http://127.0.0.1:8000/health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  # Record the pid that is actually serving, not setsid's short-lived parent.
  mediator_pids | head -1 > "$RUN/mediator.pid" 2>/dev/null || true
  if curl -sf "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
    echo -e "\n${G}  ✔ mediator restored${N} — $(curl -s http://127.0.0.1:8000/health)"
    echo -e "    Run the same task again: it now completes.\n"
  else
    err "mediator did not come back. Log: $RUN/mediator.log"
    exit 1
  fi
  exit 0
fi

# ── Stop ─────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--stop" ]]; then
  step "Stopping"
  shopt -s nullglob
  for f in "$RUN"/*.pid; do
    pid=$(cat "$f" 2>/dev/null || echo)
    name=$(basename "$f" .pid)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && log "stopped $name (pid $pid)"
    else
      warn "$name was not running"
    fi
    rm -f "$f"
  done
  echo -e "\n${G}Done.${N} Nothing else on your machine was touched.\n"
  exit 0
fi

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3<&- && return 0; return 1; }

# Never evict whatever is already on a port — on a demo machine that is
# somebody else's running application, possibly the thing being demonstrated.
for p in $MEDIATOR_PORT $DASH_PORT $AGENT_PORT $ORCH_PORT; do
  if port_busy "$p"; then
    err "Port $p is already in use. Stop that process, or run: bash run-demo.sh --stop"
    exit 1
  fi
done

# ── Pre-flight ───────────────────────────────────────────────────────────────
step "Pre-flight"

VENV="$DIR/.venv"
[[ -x "$VENV/bin/uvicorn" ]] || VENV="$(cd "$DIR/../../.." && pwd)/.venv"
if [[ ! -x "$VENV/bin/uvicorn" ]]; then
  err "No virtualenv with uvicorn found."
  err "Run:  python3 -m venv .venv && .venv/bin/pip install -e \".[dev]\""
  exit 1
fi
log "virtualenv: $VENV"

command -v node >/dev/null || { err "Node.js 18+ is required."; exit 1; }
log "node $(node --version)"

# The agent packages depend on a packed tarball of the TypeScript client, which
# is a build artifact and therefore gitignored. A fresh clone has the source but
# not the tarball, and npm fails with a bare ENOENT. Build it first.
if ! compgen -G "$DIR/clients/typescript/scml-client-*.tgz" > /dev/null; then
  warn "client tarball missing — building it"
  bash "$DIR/bootstrap.sh" > "$RUN/bootstrap.log" 2>&1 \
    || { err "client build failed. Log: $RUN/bootstrap.log"; tail -15 "$RUN/bootstrap.log"; exit 1; }
fi
log "client tarball present"

for pkg in demo-agent orchestrator; do
  if [[ ! -d "$DIR/$pkg/node_modules" ]]; then
    warn "$pkg: installing dependencies…"
    (cd "$DIR/$pkg" && npm install --silent) || { err "$pkg: npm install failed"; exit 1; }
  fi
  if [[ ! -f "$DIR/$pkg/dist/server.js" ]]; then
    warn "$pkg: building…"
    (cd "$DIR/$pkg" && npm run build --silent) || { err "$pkg: build failed"; exit 1; }
  fi
  log "$pkg ready"
done

launch() {  # launch <name> <port> <cmd...>
  local name=$1 port=$2; shift 2
  setsid nohup "$@" > "$RUN/$name.log" 2>&1 < /dev/null &
  echo $! > "$RUN/$name.pid"
  for _ in $(seq 1 40); do
    port_busy "$port" && return 0
    sleep 0.5
  done
  return 1
}

# ── Mediator ─────────────────────────────────────────────────────────────────
step "SCML mediator"

# The repo .env is production mode with docker-only hostnames and a real API
# key, all of which break a local run. Override explicitly.
if launch mediator "$MEDIATOR_PORT" env \
    DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
    "$VENV/bin/uvicorn" trust_mediator.api.app:app --host 0.0.0.0 --port "$MEDIATOR_PORT"; then
  log "mediator on :$MEDIATOR_PORT — $(curl -s "http://127.0.0.1:$MEDIATOR_PORT/health")"
else
  err "mediator failed to start. Log: $RUN/mediator.log"; tail -20 "$RUN/mediator.log"; exit 1
fi

# ── Policy ───────────────────────────────────────────────────────────────────
step "Policy"

MERGED="$RUN/merged-policy.json"
node -e '
const fs = require("fs");
const a = JSON.parse(fs.readFileSync("demo-agent/policies/policy.json", "utf8"));
const b = JSON.parse(fs.readFileSync("orchestrator/policies/policy.json", "utf8"));
// Union the agent maps; everything else comes from the orchestrator document,
// which carries the same memory/scanner/redaction settings.
const merged = { ...b, agents: { ...a.agents, ...b.agents } };
fs.writeFileSync(process.argv[1], JSON.stringify(merged, null, 2));
const names = Object.keys(merged.agents).filter(n => n !== "default");
console.log("  agents: " + names.join(", "));
' "$MERGED" || { err "policy merge failed"; exit 1; }

if node -e '
const fs = require("fs");
const policy = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
fetch(`${process.argv[2]}/v1/policy`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    policy_data: policy,
    description: "SCML demo stack — demo-agent + orchestration",
    created_by: "run-demo.sh",
    activate: true, shadow: false,
  }),
}).then(async r => {
  if (!r.ok) { console.error(await r.text()); process.exit(1); }
  console.log("  version " + (await r.json()).version_number + " active");
}).catch(e => { console.error(e.message); process.exit(1); });
' "$MERGED" "http://127.0.0.1:$MEDIATOR_PORT"; then
  log "policy loaded"
  log "denied everywhere: dispatch_container, export_customer_data, wipe_shipment_records"
else
  err "policy load failed"; exit 1
fi

# ── Dashboard ────────────────────────────────────────────────────────────────
step "Dashboard"
# Served with Cache-Control: no-store. `python3 -m http.server` lets browsers
# cache js/api.js heuristically, so an edited dashboard keeps rendering the old
# behaviour until someone does a hard refresh — which looks like the fix did
# not work rather than like a cache.
if launch dashboard "$DASH_PORT" python3 "$DIR/scripts/serve-frontend.py" "$DASH_PORT" "$DIR/frontend"; then
  log "dashboard on :$DASH_PORT"
else
  warn "dashboard failed to start (non-fatal)"
fi

# ── Agent systems ────────────────────────────────────────────────────────────
step "Agent systems"

MED_URL="http://127.0.0.1:$MEDIATOR_PORT"

if launch demo-agent "$AGENT_PORT" env \
    SCML_URL="$MED_URL" SCML_SESSION=agent-live PORT="$AGENT_PORT" \
    node "$DIR/demo-agent/dist/server.js"; then
  log "demo-agent on :$AGENT_PORT"
else
  err "demo-agent failed. Log: $RUN/demo-agent.log"; tail -10 "$RUN/demo-agent.log"
fi

if launch orchestrator "$ORCH_PORT" env \
    SCML_URL="$MED_URL" SCML_SESSION=orchestration-live PORT="$ORCH_PORT" \
    node "$DIR/orchestrator/dist/server.js"; then
  log "orchestrator on :$ORCH_PORT"
else
  err "orchestrator failed. Log: $RUN/orchestrator.log"; tail -10 "$RUN/orchestrator.log"
fi

# ── Smoke test ───────────────────────────────────────────────────────────────
step "Verifying"

verdicts=$(curl -s --max-time 20 -X POST "http://127.0.0.1:$ORCH_PORT/api/run" \
  -H 'Content-Type: application/json' \
  -d '{"task":"Handle the expedite request from Acme Freight for MSKU7834561"}' \
  | grep -o '"verdict":"[a-z_]*"' | cut -d'"' -f4 | tr '\n' ' ')

if [[ "$verdicts" == *block* ]]; then
  log "end-to-end run blocked the injected actions  [$verdicts]"
else
  warn "smoke test did not produce a block — verdicts: [$verdicts]"
fi

LAN=$(hostname -I 2>/dev/null | awk '{print $1}')

cat <<EOF

${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}
  ${W}SCML demo stack is up${N}

    Orchestration   ${C}http://localhost:$ORCH_PORT${N}   ${W}← start here${N}
    Single agent    ${C}http://localhost:$AGENT_PORT${N}
    Dashboard       ${C}http://localhost:$DASH_PORT/audit.html?api=http://localhost:$MEDIATOR_PORT&session=orchestration-live${N}
    Mediator docs   ${C}http://localhost:$MEDIATOR_PORT/docs${N}
EOF

if [[ -n "$LAN" ]]; then
cat <<EOF

  ${W}From a second laptop${N} (same network):
    export SCML_URL=http://$LAN:$MEDIATOR_PORT
    cd orchestrator && npm install && npm run build && npm start
EOF
fi

cat <<EOF

  Fail-closed demo: ${W}bash run-demo.sh --stop-mediator${N}  then  ${W}--start-mediator${N}
  Stop everything:  ${W}bash run-demo.sh --stop${N}
  Logs:             $RUN/
${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}

EOF
