# TrustMediator

Trust-aware context mediation middleware for securing agentic AI / RAG systems.
Spec: `TrustMediator_PRD (1).docx` (PRD v1.0) — the single source of truth for requirements.
Amended by `PRD_v1.1_ADDENDUM.md` (proposed), which adds what v1.0 cannot express:
storage-vs-harm ASR (§14.2a), an enforcement-coverage KPI (§14.2b), the classifier
training/eval protocol that §6.3 omitted (§6.3a), and acceptance criteria for the
production NFRs (§16). It lowers no v1.0 target. New IDs start at FR-MI-06,
FR-PE-06, FR-SC-06 — FR-MI-05 (quarantine review) and FR-PE-05 (rate limiting)
are v1.0's and unaffected.

## Working in this repo

- **Start of session:** `/session-start <role>` (prints `PROGRESS.md`, names the role, picks **one** item from `feature_list.json`). **End:** `/session-end`.
- `PROGRESS.md` — current state + newest-first session log. `feature_list.json` — the backlog; `passes: true` only with evidence that reproduces.
- `docs/DECISIONS.md` — ADRs (active / superseded / rejected; never delete). Every decision gets one.
- `FROZEN.md` — completed evidence (result files, corpora, policies, specs) with sha256. A PreToolUse hook blocks edits to these paths. If a frozen file looks wrong, report it; don't fix it.
- **New benchmark runs go to new, versioned files** (`benchmarks/results/v2/<testbed>_<YYYY-MM-DD>.{md,json}`), never over a committed baseline (ADR-0001). Use `/run-eval`.
- Module-specific rules live in `.claude/rules/*.md` and load when you touch matching paths. Read the relevant one before changing a module.
- Files are the source of truth. If code and docs disagree, stop and ask. Mark anything uncertain `[UNVERIFIED]`.
- Ask before installing system packages, changing dependencies, pushing, or spending money (paid LLM runs).

## Commands

Test env prefix (the local `.env` sets production mode, docker-only hostnames and a real API key, all of which break bare test runs):
`DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" TRUST_MEDIATOR_ADMIN_API_KEYS=""`

- Unit + integration tests: `.venv/bin/python -m pytest tests/ -q` (expect 874 passed with the `[grpc]` extra installed; integration tests need `DATABASE_URL` blank → SQLite fallback, or the docker-compose Postgres running)
- TypeScript client tests: `cd clients/typescript && npm test` (expect 25 passed; run `npm install && npm run build` first)
- Benchmarks: `.venv/bin/python -m benchmarks.cli --testbed memory_poisoning` (see `benchmarks/README.md`; the CLI pins its own env and DB, so it needs no env prefix)
- Load/latency: `.venv/bin/python -m benchmarks.load` (§8.1/§8.2 NFRs; same self-pinning env)
- Lint: `.venv/bin/python -m ruff check trust_mediator/ tests/`
- Run API locally: `.venv/bin/python -m uvicorn trust_mediator.api.app:app --reload --port 8000` (docs at /docs)
- Full stack: `docker compose up -d` (service on :8000, Postgres, Redis)
- Frozen hashes: `scripts/check_frozen.sh`

Use `python -m <tool>`, not `.venv/bin/<tool>`: the venv was created at an older path, so its console-script shebangs are broken (the interpreter symlink still works). On Windows the venv is `.venv\Scripts\python.exe`; run the same `-m` commands, or use WSL.

## Architecture rules — do not violate

Details, history and the tests that pin each rule are in `.claude/rules/`.

- **Core invariant (PRD §5.2):** data labelled `untrusted_data` or `risky_external` may inform content but must NEVER enter the control path or authorise a tool call. Preserve this in any refactor.
- **Fail policy (PRD §9):** side-effect operations (tool execution, memory writes, outbound responses) fail CLOSED on mediator error; only low-risk reads may fail open, and every fail-open must be audit-logged.
- **Taint propagation:** derived values inherit the most restrictive label of their inputs (`TrustLabel.most_restrictive`).
- **All config via env:** every tunable goes through `TRUST_MEDIATOR_*` env vars in `trust_mediator/config.py` (pydantic-settings). Never hardcode thresholds, URLs, or keys.
- **Audit everything:** every mediation decision and every control-plane action emits an audit event (SHA-256 hash chain). New decision points and admin routes must log. → `rules/audit.md`
- **A classifier that cannot score raises `ClassifierUnavailable`; it never returns 0.0.** Async callers use `scan_async`. → `rules/scanner.md`
- **Every `/v1` route takes `AuthDep`, `CallerDep` or `AdminDep`; control-plane writes take `AdminDep`. Tenant is key-bound, never client-supplied.** → `rules/api-auth.md`
- **A malformed policy must never widen authority; FR-OR-02 data-flow rules are per tenant and deny by default.** → `rules/policy.md`
- **Never classify a mediation verdict inline; the core install is the client SDK; `__all__` is the public API contract.** → `rules/clients.md`
- **Tool-output sanitization is an inbound rewrite, not an egress verdict (FR-OR-03).** → `rules/output-sanitizer.md`
- **The mediator never reads agent memory to decide authorisation.** → `rules/memory-integrity.md`
- **Traceability convention:** cite PRD requirement IDs (FR-*/NFR-*) in module docstrings and test names, as existing code does.

## Layout

- `trust_mediator/modules/` — the 8 PRD components (ingress, trust_router, injection_scanner, tool_policy, memory_integrity, output_redaction, audit_log, policy_store), one package each; `output_redaction/` also holds the FR-OR-03 `sanitizer.py` (inbound tool-output rewrite)
- `trust_mediator/core/pipeline.py` — wires the modules; the object API + SDK adapters use
- `trust_mediator/client.py` — the client SDK (`SCMLClient`/`AsyncSCMLClient`); see `rules/clients.md` for the response shapes
- `scml/` — thin alias package so `from scml import SCMLClient` works; re-exports `trust_mediator` and adds no second implementation
- `clients/typescript/` — zero-dependency Node/TS client mirroring the Python SDK method-for-method; `npm pack` produces the offline-installable tarball
- `trust_mediator/api/` — FastAPI app, routers mirror PRD §10.2 endpoints; gRPC in `api/grpc/`
- `policies/` — declarative YAML policy; `default` agent is deny-all by design
- `benchmarks/` — testbeds (InjecAgent, AgentDojo, memory poisoning), load, soak, classifier eval; results in `benchmarks/results/`
- `tests/unit/` per module, `tests/integration/test_pipeline_e2e.py` end-to-end
- `docs/recovery/` — Phase 0 analysis (2026-10-15) and the original ranked backlog; `docs/DEPLOY_VPS.md` — production runbook

## Known gaps vs PRD (backlog — don't claim these exist)

Full text: `rules/infra.md` (TLS, secrets, audit overflow), `rules/policy.md` (per-agent policy), `rules/benchmarks.md`.

- `SCANNER_BACKEND=onnx` falls back to heuristic (no trained DeBERTa model shipped)
- AgentDojo covers **all four suites** but only **two attacks of seventeen**. Do not describe AgentDojo coverage as complete.
- No sandboxed tool executor (PRD §11) — tool execution stays in the host app
- `PUT /v1/policy` still replaces the whole document; per-agent `PUT /v1/policy/agents/{id}` is the routine path
- TLS is supported but no shipped deployment except `docker-compose.prod.yml` (Caddy) terminates TLS; Postgres, Redis and Kafka connections are plaintext
- Secrets: `<VAR>_FILE` sources exist; only API keys rotate live
- Audit overflow is recorded (`audit_gap`), not prevented; no spill-to-disk
- Soak availability (100.000%) is in-process only, not a production uptime SLO

## Measured state (PRD §14.2) — do not overstate

Full numbers, caveats and what has already been tried and rejected: `rules/benchmarks.md`. Headlines, each of which must be quoted *with* its caveat:

- **Memory poisoning:** 20.8% storage ASR vs < 10% target — §14.2 NOT met. Harm 18.8% pessimistic. Report both.
- **InjecAgent (1054 external cases):** all five §14.2 KPIs pass, but `no_tool_policy` is 100.0% ASR: tool policy is the *entire* defence, and **the injection scanner detects 0 of 1054**.
- **AgentDojo:** ASR 29.0% → 7.3% (949 attacked cases) for 19% of benign utility (74.2% → 59.8%). Quote benign utility, never attacked. CaMeL is better on both axes.
- **§6.3 detection:** no backend reaches FR-SC-07 (AUC 0.85). Best: affordance detector 0.779 (no-go), LLM 0.72 (also fails latency).
- Never tune against the in-house memory-poisoning corpus. Classifier work trains on external data and evaluates against the in-house corpus as held-out, never the reverse.
