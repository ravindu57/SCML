# TrustMediator

**Trust-Aware Context Mediation Middleware for Securing Agentic AI and RAG Systems**

[![Tests](https://img.shields.io/badge/tests-182%20passed-brightgreen)](tests/) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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
cd "scml - middleware layer secure"

# Deploy everything (installs Docker if needed, builds image, starts stack)
sudo bash deploy.sh
```

The service will be live at **http://localhost:8000**.

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
.venv/bin/pytest tests/ -v
# Expected: 182 passed
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
| Availability (NFR-AVAIL-01) | ≥ 99.9% | not measured | — |

Audit writes are batched into one transaction per drain (`AUDIT_BATCH_MAX`),
sustaining ~2,800 events/s. Per-event writes measured ~140 events/s and were
the throughput ceiling — the queue grew in memory rather than adding latency,
which is why it took a load test to find. Details in
[`benchmarks/README.md`](benchmarks/README.md).

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
