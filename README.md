# TrustMediator

**Trust-Aware Context Mediation Middleware for Securing Agentic AI and RAG Systems**

[![Tests](https://img.shields.io/badge/tests-64%20passed-brightgreen)](tests/) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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
# Expected: 64 passed
```

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

## License

MIT
