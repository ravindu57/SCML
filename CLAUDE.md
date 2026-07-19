# TrustMediator

Trust-aware context mediation middleware for securing agentic AI / RAG systems.
Spec: `TrustMediator_PRD (1).docx` (PRD v1.0) — the single source of truth for requirements.

## Commands

- Unit + integration tests: `.venv/bin/pytest tests/ -q` (expect 64 passed; integration tests need `DATABASE_URL` blank → SQLite fallback, or the docker-compose Postgres running)
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

## Known gaps vs PRD (backlog — don't claim these exist)

- No gRPC API (REST only); `SCANNER_BACKEND=onnx` falls back to heuristic (no trained model shipped)
- No benchmark harness yet (AgentDojo / InjecAgent / memory-poisoning testbed — PRD §14)
- Rate limiter is in-memory per-process; needs Redis for multi-worker correctness
