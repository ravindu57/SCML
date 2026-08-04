# TrustMediator

Trust-aware context mediation middleware for securing agentic AI / RAG systems.
Spec: `TrustMediator_PRD (1).docx` (PRD v1.0) — the single source of truth for requirements.

## Commands

- Unit + integration tests: `.venv/bin/pytest tests/ -q` (expect 142 passed; integration tests need `DATABASE_URL` blank → SQLite fallback, or the docker-compose Postgres running)
- Benchmarks: `.venv/bin/python -m benchmarks.cli --testbed memory_poisoning` (see `benchmarks/README.md`; the CLI pins its own env and DB, so it needs no env prefix)
- Load/latency: `.venv/bin/python -m benchmarks.load` (§8.1/§8.2 NFRs; same self-pinning env)
- Lint: `.venv/bin/ruff check trust_mediator/ tests/`
- Run API locally: `.venv/bin/uvicorn trust_mediator.api.app:app --reload --port 8000` (docs at /docs)
- Full stack: `docker compose up -d` (service on :8000, Postgres, Redis)

## Architecture rules — do not violate

- **Core invariant (PRD §5.2):** data labelled `untrusted_data` or `risky_external` may inform content but must NEVER enter the control path or authorise a tool call. Preserve this in any refactor.
- **Fail policy (PRD §9):** side-effect operations (tool execution, memory writes, outbound responses) fail CLOSED on mediator error; only low-risk reads may fail open, and every fail-open must be audit-logged.
- **Taint propagation:** derived values inherit the most restrictive label of their inputs (`TrustLabel.most_restrictive`).
- **All config via env:** every tunable goes through `TRUST_MEDIATOR_*` env vars in `trust_mediator/config.py` (pydantic-settings). Never hardcode thresholds, URLs, or keys.
- **Audit everything:** every mediation decision emits an `AuditEvent` through `AuditLogger` (SHA-256 hash chain). New decision points must log.
- **Traceability convention:** cite PRD requirement IDs (FR-*/NFR-*) in module docstrings and test names, as existing code does.

## Layout

- `trust_mediator/modules/` — the 8 PRD components (ingress, trust_router, injection_scanner, tool_policy, memory_integrity, output_redaction, audit_log, policy_store), one package each
- `trust_mediator/core/pipeline.py` — wires the modules; the object API + SDK adapters use
- `trust_mediator/api/` — FastAPI app, routers mirror PRD §10.2 endpoints
- `policies/` — declarative YAML policy; `default` agent is deny-all by design
- `tests/unit/` per module, `tests/integration/test_pipeline_e2e.py` end-to-end

## Production infrastructure

- gRPC transport: `trust_mediator/api/grpc/` (proto + generated stubs + grpc.aio server); enable via `TRUST_MEDIATOR_GRPC_ENABLED`. Regeneration instructions in that package's `__init__.py`. Generated `mediation_pb2*.py` are ruff-excluded — never hand-edit them.
- Rate limiting: Redis-backed cluster-wide when `REDIS_URL` set (`modules/tool_policy/rate_limiter.py`), per-process in-memory otherwise.
- Audit fan-out: Kafka (`modules/audit_log/kafka_forwarder.py`, optional `[kafka]` extra) + SIEM webhook; DB hash chain is authoritative.
- Deploy: `k8s/` (gateway + sidecar), `.github/workflows/ci.yml` (lint, 3.11/3.12 tests, docker smoke).
- Test commands must pass `DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS=""` — the local `.env` sets production mode, docker-only hostnames, and a real API key, all of which break bare pytest runs.
- Audit chain integrity is enforced transactionally in `AuditRepository.append_chained` (row lock + unique (session_id, seq_no)); never reintroduce per-process chain state in AuditLogger.
- Tracing: `trust_mediator/observability.py` (NFR-OBS-01). Spans wrap every pipeline decision point. Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set; export needs the `[otlp]` extra. **Span attributes carry decisions/labels/scores only — never mediated content**, since spans leave the process for a collector the mediator does not control. `test_spans_never_carry_mediated_content` enforces this.

## Known gaps vs PRD (backlog — don't claim these exist)

- `SCANNER_BACKEND=onnx` falls back to heuristic (no trained DeBERTa model shipped)
- No AgentDojo / InjecAgent testbeds yet — only the memory-poisoning testbed exists (PRD §14.1)
- No sandboxed tool executor (PRD §11) — tool execution stays in the host app
- No TLS/mTLS between components (NFR-SEC-03) and no secrets manager (NFR-SEC-04)
- NFR-AVAIL-01 (99.9%) is unmeasured — no soak or fault-injection test exists
- Audit writer saturates at ~140 events/s (`benchmarks/results/load.md`). The request path sustains 246 req/s, so above ~140 req/s the unbounded audit queue grows in memory and drops decisions on shutdown — an FR-AL-01 risk, not a latency one. Cause is the per-event transaction in `AuditRepository.append_chained`, not SQLite.

## Measured state (PRD §14.2) — do not overstate

`benchmarks/results/memory_poisoning.md` is the committed baseline. As of the
last run the memory integrity layer measures **33.3% ASR against a < 10%
target**; §14.2 acceptance is NOT met. Residual failures are concentrated in
families no shipped detector matches (`tool_hijack`, `authority_spoof`) —
that gap needs the §6.3 classifier, not more scoring rules.

When changing the scorer, thresholds or detectors, re-run the benchmark and
update the committed result. Do not tune weights or add regex patterns until
this corpus passes: it was written in-house, so that is overfitting, not a
result. External validation (AgentDojo / InjecAgent) has to come first.
