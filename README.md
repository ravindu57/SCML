# TrustMediator

**Trust-Aware Context Mediation Middleware for Securing Agentic AI and RAG Systems**

[![Tests](https://img.shields.io/badge/tests-297%20passed%20%7C%20303%20with%20grpc-brightgreen)](tests/) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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

`deploy.sh` starts the API only. To bring up the API **and** the web dashboard
together:

```bash
bash start.sh     # API :8000 + dashboard :3000 + agent orchestrator :3001
bash stop.sh      # tear it all down
```

Six pages, all reading live data from the API:

| Page | URL | Shows |
|---|---|---|
| Command Center | http://localhost:3000/index.html | Latency, throughput, live audit trail |
| Live Agent Demo | http://localhost:3000/demo.html | An agent driven through the mediator in real time |
| Traffic | http://localhost:3000/traffic.html | Per-decision feed: allow / block / quarantine |
| Tool Policies | http://localhost:3000/policy.html | Per-agent allow-lists, redaction rules, version history |
| Memory Integrity | http://localhost:3000/memory.html | Quarantined writes awaiting review, integrity scores |
| Audit Logs | http://localhost:3000/audit.html | Full replay with hash-chain verification |

The dashboard is static HTML — no build step. It talks to `http://localhost:8000`,
so the API must be running.

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
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest tests/ -q
# Expected: 297 passed, 1 skipped
```

The skip is `tests/integration/test_grpc_api.py`, which needs the optional gRPC
transport. Install that extra to run the full suite:

```bash
.venv/bin/pip install -e ".[dev,grpc]"
.venv/bin/pytest tests/ -q
# Expected: 303 passed
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
