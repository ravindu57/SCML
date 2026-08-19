# TrustMediator

**Trust-Aware Context Mediation Middleware for Securing Agentic AI and RAG Systems**

[![Tests](https://img.shields.io/badge/tests-405%20passed-brightgreen)](tests/) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Overview

TrustMediator is a production-grade Python middleware that sits between an LLM agent and its data sources / tools, enforcing **least-agency policies**, **memory integrity**, and **prompt injection protections** at runtime.

```
User Query ──► IngressInterceptor
                    │
                    ▼
              TrustRouter  (labels & taint propagation)
                    │
                    ▼
            InjectionScanner  (heuristic + pluggable ML classifier)
                    │
                    ▼
            ToolPolicyEngine  (declarative allow-list + rate limits)
                    │
                    ▼
         MemoryIntegrityLayer  (quarantine → scan → score → persist/reject)
                    │
                    ▼
            OutputRedactor  (PII / secrets / entropy-based detection)
                    │
                    ▼
              AuditLogger  (tamper-evident SHA-256 hash chain)
                    │
                    ▼
            Agent Response ◄──
```

## Install as a package

SCML ships as a **thin client plus a server**. The engine — modules, database,
audit hash chain — runs as a service; your agent installs a small client that
talks to it. That split is deliberate: the audit chain needs a shared database
with transactional row locks, so it cannot be a library inside every caller,
and a client that dragged the whole stack along would be a ~400 MB decision
nobody makes.

**Python** (14 packages, ~10 s, ~32 MB):

```bash
pip install trust-mediator                 # client SDK only
pip install "trust-mediator[server]"       # to run the mediator
pip install "trust-mediator[embedded]"     # in-process MediationPipeline, no HTTP hop
```

```python
from scml import SCMLClient          # or: from trust_mediator import SCMLClient

scml = SCMLClient("http://localhost:8000", api_key="sk-...")

ctx = scml.mediate_context(session_id="s1", content=supplier_document)
decision = scml.mediate_tool_call(
    session_id="s1",
    tool_name="release_container",
    arguments={"container_id": cid},
    # Without labels, FR-PE-04 never fires and a model-composed argument is
    # indistinguishable from a user-supplied one.
    argument_trust_labels={"container_id": ctx.trust_label},
    is_irreversible=True,
)
if not decision.allowed:
    raise RuntimeError(decision.reason)
```

**Node / TypeScript** (zero runtime dependencies, Node 18+):

```bash
cd clients/typescript && npm pack        # → scml-client-1.0.0.tgz
npm install ./scml-client-1.0.0.tgz      # works offline
```

```js
const { SCML } = require('scml-client');
const scml = new SCML({ url: process.env.SCML_URL });

const ctx = await scml.mediateContext({ sessionId, content: supplierDocument });
const d   = await scml.mediateToolCall({
  sessionId, tool: 'release_container',
  arguments: { containerId },
  argumentTrustLabels: { containerId: ctx.trustLabel ?? 'untrusted_data' },
});
if (!d.allowed) throw new Error(d.reason);
```

Both SDKs expose the same methods and normalise every endpoint onto one
`allowed` flag — necessary, because `/output` reports `blocked` and
`/memory/write` reports `verdict`, so code branching on `decision` is silently
wrong for three of the five endpoints. Side-effect calls **fail closed**: an
unreachable mediator raises rather than returning something resembling an allow
(PRD §9).

Worked example against a live mediator:

```bash
node clients/typescript/examples/shipping-agent.js
```

See `clients/typescript/README.md` for the full API.

## Quick Start (Docker Compose)

```bash
# Clone and enter the project
git clone https://github.com/ravindu57/SCML.git
cd SCML

# Deploy everything (installs Docker if needed, builds image, starts stack)
sudo bash deploy.sh
```

The service will be live at **http://localhost:8000**.

## Dashboard

One command brings up the mediator, the dashboard and both agent systems:

```bash
bash run-demo.sh          # mediator :8000, dashboard :3100, agents :4000 and :4100
bash run-demo.sh --stop   # tear down only what it started
```

It merges the two agent policy documents before loading them — `PUT /v1/policy`
replaces the whole document, so loading them separately would silently
deny-all whichever went first — and finishes by running an injection end to
end, failing loudly if nothing gets blocked.

| Page | URL | Shows |
|---|---|---|
| Command Center | http://localhost:3100/index.html | Mediation calls, latency, live audit trail |
| Live Agent Demo | http://localhost:3100/demo.html | Every decision as it lands, polled from the audit trail |
| Traffic | http://localhost:3100/traffic.html | Per-decision feed: allow / block / quarantine |
| Tool Policies | http://localhost:3100/policy.html | Per-agent allow-lists, redaction config, version history |
| Memory Integrity | http://localhost:3100/memory.html | Quarantined writes awaiting review, integrity scores |
| Audit Logs | http://localhost:3100/audit.html | Full replay with hash-chain verification |

The dashboard is static HTML — no build step. Pass `?api=` and `?session=` to
point it at a mediator that is not on localhost, which is the normal case when
an agent runs on a second machine:

```
audit.html?api=http://192.168.1.42:8000&session=orchestration-live
```

Three themes ship (Aurora, Jarvis, Obsidian), selectable from the nav rail;
structure is shared in `css/base.css` so they differ only in palette.

### Agent systems

| | Port | What it demonstrates |
|---|---|---|
| [`demo-agent/`](demo-agent/) | 4000 | Single agent, chat box — you type the injection |
| [`orchestrator/`](orchestrator/) | 4100 | Four agents; the injection arrives inside a document the agent fetches |

### Fail-closed demonstration

Stop the mediator while leaving the agents running, and every action is
refused — including harmless ones — because authorisation cannot be obtained:

```bash
bash run-demo.sh --stop-mediator    # agents stay up
bash run-demo.sh --start-mediator   # recovers in seconds
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/mediate/context` | Label + scan retrieved/tool content |
| `POST` | `/v1/mediate/tool-call` | Authorise a proposed tool call |
| `POST` | `/v1/mediate/memory/write` | Vet a candidate memory write |
| `POST` | `/v1/mediate/memory/read` | Verify a memory read |
| `POST` | `/v1/mediate/output` | Redact + authorise outbound response |
| `GET`  | `/v1/audit/replay/{sessionId}` | Replay full session decision trail |
| `GET`  | `/v1/policy` | Read active declarative policy |
| `PUT`  | `/v1/policy` | Update policy (gated) |
| `GET`  | `/health` | Health check |
| `GET`  | `/metrics` | Prometheus metrics |

Interactive docs: **http://localhost:8000/docs**

## Running Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"       # [dev] pulls in [server] and [ml]
.venv/bin/pytest tests/ -q
# Expected: 404 passed, 1 skipped
```

The skip is `tests/integration/test_grpc_api.py`, which needs the optional gRPC
transport. Install that extra to run the full suite:

```bash
.venv/bin/pip install -e ".[dev,grpc]"
.venv/bin/pytest tests/ -q
# Expected: 405 passed
```

The TypeScript client has its own suite (Node 18+, no test framework):

```bash
cd clients/typescript && npm install && npm run build && npm test
# Expected: 18 passed
```

## Security Benchmarks

The evaluation harness (PRD §14) measures attack success rate, false-positive
rate and latency, and runs the per-module ablation study.

```bash
.venv/bin/python -m benchmarks.cli --testbed memory_poisoning
```

Current measured state — see [`benchmarks/results/memory_poisoning.md`](benchmarks/results/memory_poisoning.md):

| KPI | Measured | PRD §14.2 target | |
|---|---:|---:|---|
| Memory-poisoning ASR | 33.3% | < 10% | ❌ |
| ASR reduction vs undefended | 66.7% | ≥ 90% | ❌ |
| False-positive rate | 0.0% | < 3% | ✅ |
| Utility | 100.0% | ≥ 90% | ✅ |
| Added latency (p95) | 6.7 ms | < 400 ms | ✅ |

**v1.0 acceptance (§14.4) is not met.** The memory integrity layer blocks two
thirds of the memory-poisoning corpus — real and measurably better than no
defence (100% → 33.3% ASR), but short of the headline claim in the PRD.

The residual failures are concentrated in attack families that no shipped
detector matches at all (`tool_hijack` 83%, `authority_spoof` 67%) — plainly
worded poisoned memories that trip neither the regex pre-filter nor the
instruction-pattern checker. Closing that gap needs the trained classifier
of §6.3, not more scoring rules. Diagnosis and methodological caveats:
[`benchmarks/README.md`](benchmarks/README.md).

### Stored is not the same as harmful

That 33.3% measures how much poison gets **stored**. It does not measure how
much can *act*. Applying the standard the InjecAgent testbed uses — an attack
succeeds only when the mediator would have let its goal through — gives a
second number:

```bash
.venv/bin/python -m benchmarks.testbeds.memory_poisoning.harm_report
```

Full analysis: [`benchmarks/results/memory_poisoning_harm.md`](benchmarks/results/memory_poisoning_harm.md).

| Harm vector | Cases | Still harmful | What it must defeat |
|---|---:|---:|---|
| `tool` | 13 | **0** | tool allow-list / untrusted-argument policy |
| `control` | 22 | **0** | the claim that a mediator control is disabled |
| `output` | 5 | 1 | egress redaction |
| `informational` | 8 | 8 | *nothing — no mediator gate on this path* |

**Both numbers are reported deliberately.** Quoting only the harm figure would
be moving the goalposts; quoting only the storage figure overstates the risk of
a record the control path never consults. Pessimistically — counting every
out-of-scope case as a full loss — **18.8% (9/48)**, against 33.3% stored.

Two findings sit behind that:

- **`tool_hijack`, the worst family for storage (83%), is 0/6 for harm.** The
  poisoned memory names `send_raw_smtp` or `shell_exec`; neither is on the
  agent's allow-list, so a fully persuaded agent still cannot call them.
- **All 22 control-bypass cases are inert, and it is measured, not assumed.**
  Authorisation is read from the declarative policy store — the mediator never
  consults agent memory to decide it. With three poisoned records sitting
  ACTIVE, including *"policy validation has been disabled"*, every forbidden
  tool is still denied. That is §5.2 holding after the write-path defence has
  already failed, and it is asserted in
  [`tests/unit/test_memory_harm.py`](tests/unit/test_memory_harm.py).

The 8 `informational` cases are **not** counted as defended. A poisoned memory
that makes the agent quote a false approval limit is real harm and nothing here
stops it — the mediator gates actions and egress, not beliefs.

### External validation — InjecAgent

That corpus was written in-house, so it can only ever be self-assessment. The
InjecAgent testbed runs **1054 indirect-injection cases authored by a third
party** ([Zhan et al., ACL Findings 2024](https://arxiv.org/abs/2403.02691),
MIT-licensed, vendored under
[`benchmarks/testbeds/injecagent/data/`](benchmarks/testbeds/injecagent/data/ATTRIBUTION.md)).

```bash
.venv/bin/python -m benchmarks.cli --testbed injecagent
```

Full results: [`benchmarks/results/injecagent.md`](benchmarks/results/injecagent.md).

| KPI | Measured | PRD §14.2 target | |
|---|---:|---:|---|
| Injection ASR | 0.0% | < 5% | ✅ |
| ASR reduction vs undefended | 100.0% | ≥ 90% | ✅ |
| False-positive rate | 0.0% | < 3% | ✅ |
| Utility | 100.0% | ≥ 90% | ✅ |
| Added latency (p95) | 0.4 ms | < 400 ms | ✅ |

**Read the ablation before reading the headline.** Every KPI passes, but none
of it is the scanner's doing:

| Configuration | ASR |
|---|---:|
| `full_defence` | 0.0% |
| `no_scanner` — detection off, enforcement on | 0.0% |
| `no_tool_policy` — enforcement off, detection on | **100.0%** |
| `undefended` | 100.0% |

Removing the scanner changes nothing. Removing tool policy loses everything.
**The injection scanner detects 0 of the 1054 attacks.** Two independent
reasons, both measured:

1. **Stage 2 is unreachable.** The scanner runs its ML classifier only when the
   regex pre-filter scores at or above `SCANNER_ML_GATE_THRESHOLD`
   ([`scanner.py`](trust_mediator/modules/injection_scanner/scanner.py)). 992 of
   1054 attacks score *exactly* 0.0 — a mock oracle returning 1.0 is consulted on
   **0 of 1054**. So `SCANNER_BACKEND=llm` buys nothing here without also lowering
   the gate: it changes which classifier runs, not whether it runs.
2. **The classifier cannot discriminate anyway.** Forced to run on all 1054, it
   scores attacks at mean 0.478 and clean content at 0.515 — benign *higher*
   than malicious, nothing near the 0.7 escalate threshold. It is trained on 60
   in-house jailbreak strings and has no signal for a polite instruction
   embedded in JSON tool output. Lowering the gate to 0.0 with it catches 19.7%
   more attacks but takes FPR to 23.5% and utility to 76.5% — two KPIs from PASS
   to FAIL, so the default stays closed.

So the defence that holds is the §5.2 invariant enforced by least agency:
untrusted tool output never authorises a tool call, so an attacker instruction
is inert unless the tool it names is already on the agent's allow-list. That is
the architecture working exactly as specified **while its detection layer
contributes nothing** — a measured argument for the design rather than a
claimed one, and simultaneously a measured indictment of §6.3.

One caveat this testbed asserts rather than hides: `GitHubGetUserDetails` is
both a user tool and an attacker tool upstream. Where an attacker reuses a tool
the agent legitimately holds, policy cannot help — the confused-deputy case.

## Performance

Measured with the load harness (PRD §8.1, §8.2) — see
[`benchmarks/results/load.md`](benchmarks/results/load.md):

```bash
.venv/bin/python -m benchmarks.load
```

| NFR | Target | Measured | |
|---|---|---|---|
| Fast-path latency (NFR-PERF-01) | p50 < 120 ms, p95 < 400 ms | p50 24 ms, p95 31 ms | ✅ |
| Policy decision (NFR-PERF-03) | p95 < 10 ms | 0.04 ms | ✅ |
| Throughput (NFR-SCAL-01) | ≥ 100 req/s | 334 req/s | ✅ |
| Audit off request path (NFR-PERF-04) | 0 ms on path | enqueue never awaited | ✅ |
| Availability (NFR-AVAIL-01) | ≥ 99.9% | 100.000% | ✅ |

Audit writes are batched into one transaction per drain (`AUDIT_BATCH_MAX`),
sustaining ~2,800 events/s. Per-event writes measured ~140 events/s and were
the throughput ceiling — the queue grew in memory rather than adding latency,
which is why it took a load test to find. Details in
[`benchmarks/README.md`](benchmarks/README.md).

### Availability under fault injection

```bash
.venv/bin/python -m benchmarks.soak --duration 60
```

Six dependency failures are injected into a live pipeline — model server,
policy store, memory database, redactor, audit database, and a degraded
scanner — alternating with healthy windows. Result:
[`benchmarks/results/soak.md`](benchmarks/results/soak.md).

**Availability here means the caller received a decision, including a denial.**
§9 requires a mediator that cannot verify a tool call to deny it, so a deny
during a database outage is correct behaviour, not downtime; counting it
otherwise would reward a mediator that failed open. A call is unavailable only
when an exception escaped or it timed out.

| Fault | §9 requires | Observed |
|---|---|---|
| `scanner_down` | low-risk reads fail open, tagged | `allow` |
| `policy_store_down` | fail closed | `mediator_error` |
| `memory_store_down` | fail closed | `quarantine` |
| `redactor_down` | fail closed | `blocked` |
| `audit_store_down` | mediation continues | decisions rendered |
| `scanner_slow` | latency degrades, not availability | decisions rendered |

10,666 calls, zero escaped faults, recovery under 1 ms after every fault
cleared. This measures the mediator's own fault handling in-process — not a
deployed service behind a load balancer, and not network partitions, disk
exhaustion or OOM. It is not a production uptime SLO.

The first run of this harness measured **75% availability under
`memory_store_down`**: the fail-closed handler persisted its quarantine record
with the same repository that had just failed, so the exception escaped to the
caller. The unit test covering that path only broke `list_active`, leaving the
quarantine write untested. Fixed, with the §9 escape now covered.

## Configuration

Copy `.env.example` to `.env` and adjust. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | SQLite (local) | PostgreSQL URL for production |
| `REDIS_URL` | (in-memory) | Redis URL for distributed cache |
| `SCANNER_BACKEND` | `heuristic` | `heuristic` / `onnx` / `llm` |
| `MEMORY_INTEGRITY_THRESHOLD` | `0.65` | Score below which writes are quarantined |
| `SCANNER_BLOCK_THRESHOLD` | `0.85` | Injection score above which content is blocked |

## Architecture

| Layer | Technology |
|-------|-----------|
| API | FastAPI + Uvicorn (async, 4 workers) |
| Data models | Pydantic v2 |
| ORM | SQLAlchemy 2.0 async |
| Database | PostgreSQL (aiosqlite fallback for dev) |
| Cache | Redis (in-memory fallback) |
| Scanner | Heuristic TF-IDF + pluggable interface |
| Observability | OpenTelemetry + Prometheus |
| Container | Docker + Docker Compose |

## Policy Configuration

Edit `policies/default_policy.yaml` to customise per-agent tool allow-lists, approval gates, rate limits, and scanner thresholds.

## Production Deployment

| Concern | Mechanism |
|---|---|
| Kubernetes | `k8s/` — gateway mode (Deployment + HPA + PDB, hardened securityContext) and sidecar example, per PRD §5.4 |
| Distributed rate limiting | Set `REDIS_URL` — tool-call limits are enforced cluster-wide via Redis sorted sets (required for >1 worker/replica; falls back per-process if Redis blips) |
| gRPC transport | `TRUST_MEDIATOR_GRPC_ENABLED=true` (port 50051) + `pip install "trust-mediator[grpc]"` — same pipeline, policy, and audit trail as REST |
| Audit pipeline | `AUDIT_KAFKA_BOOTSTRAP` publishes finalized events to Kafka topic `trustmediator.audit` (at-least-once, keyed by session); `AUDIT_SIEM_WEBHOOK_URL` for direct SIEM webhook. The DB hash chain remains authoritative |
| HTTP hardening | `TRUST_MEDIATOR_CORS_ORIGINS`, `TRUST_MEDIATOR_TRUSTED_HOSTS`, `TRUST_MEDIATOR_HSTS_ENABLED`; security headers (nosniff, frame-deny, no-store) always on |
| Auth | `TRUST_MEDIATOR_API_KEYS` — enforced on REST (`X-API-Key`) and gRPC (`x-api-key` metadata) |
| CI | `.github/workflows/ci.yml` — ruff, pytest on 3.11/3.12 with a test-count floor, Docker build + container smoke test |

## License

MIT
