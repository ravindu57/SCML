# TrustMediator

Trust-aware context mediation middleware for securing agentic AI / RAG systems.
Spec: `TrustMediator_PRD (1).docx` (PRD v1.0) — the single source of truth for requirements.
Amended by `PRD_v1.1_ADDENDUM.md` (proposed), which adds what v1.0 cannot express:
storage-vs-harm ASR (§14.2a), an enforcement-coverage KPI (§14.2b), the classifier
training/eval protocol that §6.3 omitted (§6.3a), and acceptance criteria for the
production NFRs (§16). It lowers no v1.0 target. New IDs start at FR-MI-06,
FR-PE-06, FR-SC-06 — FR-MI-05 (quarantine review) and FR-PE-05 (rate limiting)
are v1.0's and unaffected.

## Commands

- Unit + integration tests: `.venv/bin/pytest tests/ -q` (expect 394 passed; integration tests need `DATABASE_URL` blank → SQLite fallback, or the docker-compose Postgres running)
- TypeScript client tests: `cd clients/typescript && npm test` (expect 18 passed; run `npm install && npm run build` first)
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
- **Async callers use `InjectionScanner.scan_async`, never `scan`.** `scan` runs stage 2 inline, and `LLMClassifier.predict` bridges to async by blocking on `Future.result()` — a 1s classifier call measured 4 event-loop iterations instead of ~100, stalling every concurrent request, not just its own. A backend that performs I/O must override `predict_async`; the base class default delegates to `predict`, which is correct only for CPU-bound backends. `test_scanner_async_path.py` asserts both call sites.
- **Traceability convention:** cite PRD requirement IDs (FR-*/NFR-*) in module docstrings and test names, as existing code does.
- **The core install is the client SDK; the server stack lives in extras.** `pip install trust-mediator` must stay ~14 packages (`httpx`, `pydantic`, `pydantic-settings`). Everything else is `[server]`, `[ml]` (scikit-learn only, imported lazily in `HeuristicClassifier.train`), `[embedded]`. `[dev]` self-references `[server,ml]` so `pip install -e ".[dev]"` still gives a full stack. The `client-install` CI job fails if a server dependency leaks back into core — if you add a core dependency, that job is the thing telling you not to.
- **`__all__` in `trust_mediator/__init__.py` is the public API contract.** Adding to it is a minor version; removing or renaming is a major one. Everything under `modules/`, `db/`, `api/` is internal and free to change. `MediationPipeline` and `settings` resolve lazily via module `__getattr__` so a client-only install can import the package without the server stack — do not make them eager. `test_public_api.py` pins all of this.
- **Never classify a mediation verdict inline.** `client.classify_decision` is the single implementation, shared by the SDK and the LangChain guard. `require_approval` and `deny` both arrive *suffixed* (`.irreversible`, `.schema_violation`), and an unrecognised verdict must map to `unknown`, never `allow` — matching `require_approval` exactly once let gated irreversible actions through (FR-PE-03). The TypeScript client mirrors the same branch order and must stay in sync.

## Layout

- `trust_mediator/modules/` — the 8 PRD components (ingress, trust_router, injection_scanner, tool_policy, memory_integrity, output_redaction, audit_log, policy_store), one package each
- `trust_mediator/core/pipeline.py` — wires the modules; the object API + SDK adapters use
- `trust_mediator/client.py` — the client SDK (`SCMLClient`/`AsyncSCMLClient`). Normalises the five mediation endpoints, which return three different shapes: `/context` and `/tool-call` carry `decision`, `/output` carries `blocked` and **no `decision` at all**, `/memory/write` carries `verdict`. Callers branch on `result.allowed`, never on a raw field.
- `scml/` — thin alias package so `from scml import SCMLClient` works; re-exports `trust_mediator` and adds no second implementation
- `clients/typescript/` — zero-dependency Node/TS client mirroring the Python SDK method-for-method; `npm pack` produces the offline-installable tarball
- `trust_mediator/api/` — FastAPI app, routers mirror PRD §10.2 endpoints
- `policies/` — declarative YAML policy; `default` agent is deny-all by design
- `tests/unit/` per module, `tests/integration/test_pipeline_e2e.py` end-to-end

## Production infrastructure

- gRPC transport: `trust_mediator/api/grpc/` (proto + generated stubs + grpc.aio server); enable via `TRUST_MEDIATOR_GRPC_ENABLED`. Regeneration instructions in that package's `__init__.py`. Generated `mediation_pb2*.py` are ruff-excluded — never hand-edit them.
- Rate limiting: Redis-backed cluster-wide when `REDIS_URL` set (`modules/tool_policy/rate_limiter.py`), per-process in-memory otherwise.
- Audit fan-out: Kafka (`modules/audit_log/kafka_forwarder.py`, optional `[kafka]` extra) + SIEM webhook; DB hash chain is authoritative.
- Deploy: `k8s/` (gateway + sidecar), `.github/workflows/ci.yml` (lint, 3.11/3.12 tests, docker smoke).
- Test commands must pass `DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS=""` — the local `.env` sets production mode, docker-only hostnames, and a real API key, all of which break bare pytest runs.
- Audit chain integrity is enforced transactionally in `AuditRepository.append_chained` / `append_chained_batch` (row lock + unique (session_id, seq_no)); never reintroduce per-process chain state in AuditLogger. The batch variant re-reads each session's tail under the lock inside its own transaction, so it is safe across workers — chaining in memory is only valid *within* one locked transaction.
- `AuditLogger.log()` must never block or await — it is on the request path (NFR-PERF-04). Overflow drops and records; it does not apply back-pressure. `log_async()` is the awaiting variant, for off-path callers only. Eviction under `drop_oldest` pairs every `get_nowait()` with a `task_done()`, or `stop()` hangs on `join()`.
- The audit writer coalesces queued events into one transaction per batch (`AUDIT_BATCH_MAX`, default 128). Per-event writes measured ~140 events/s and made audit the throughput ceiling; batching lifts it to ~2,800/s across 50 sessions. Throughput falls as session fan-out rises (one locked tail read per session per batch). `AUDIT_BATCH_MAX=1` restores the old behaviour.
- LangChain guard (`integrations/langchain_guard.py`): callbacks are notification-only, so the hooks scan and audit but cannot alter data in flight. The only enforcement points are `strict=True` (raises, aborting the run) and `guard.redact(text)` (returns safe text for the caller to substitute). It sends `argument_trust_labels` by default — without them FR-PE-04 never fires and a model-composed argument sails through as `allow`. It also prefers LangChain's structured `inputs` dict over the flat string, or declared `argument_schema`s can never match. Don't "simplify" either back.
- Tracing: `trust_mediator/observability.py` (NFR-OBS-01). Spans wrap every pipeline decision point. Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set; export needs the `[otlp]` extra. **Span attributes carry decisions/labels/scores only — never mediated content**, since spans leave the process for a collector the mediator does not control. `test_spans_never_carry_mediated_content` enforces this.

## Known gaps vs PRD (backlog — don't claim these exist)

- `SCANNER_BACKEND=onnx` falls back to heuristic (no trained DeBERTa model shipped)
- No AgentDojo testbed yet. The InjecAgent testbed **does** exist
  (`benchmarks/testbeds/injecagent/`, 1054 external cases) — see "Measured state"
- No sandboxed tool executor (PRD §11) — tool execution stays in the host app
- **The policy document is single-tenant.** `PUT /v1/policy` replaces the whole
  document, `agents` map and all, so two teams administering different agents
  on one mediator will clobber each other — last write wins, and the loser gets
  silently deny-alled via the `default` fallback (`engine.py:74`). Today's
  workable answers are one mediator per system, or one owner of the document.
  A per-agent endpoint (`PUT /v1/policy/agents/{id}`) is the proper fix and is
  not built. This matters the moment SCML is pitched as shared infrastructure:
  the SDK installs in seconds, but onboarding a second team does not.
- Policy identity is per `agent_id`, and an unknown `agent_id` falls back to
  `default` (deny-all). That is the correct fail-closed default, but it means
  "install the SDK" never means "it works" — a new integration is fully denied
  until someone writes policy for it. Grant authority per workflow, not per
  system: `truelane-w1`…`truelane-w8` exist so a compromised intake step cannot
  borrow the invoicing workflow's authority. A shared agent id makes the
  allow-list the union of everything any workflow needs.
- No TLS/mTLS between components (NFR-SEC-03) and no secrets manager (NFR-SEC-04)
- ~~NFR-AVAIL-01 unmeasured~~ — **measured**: `benchmarks/soak/` injects six
  dependency failures into a live pipeline; committed result
  `benchmarks/results/soak.md` shows 100.000% over 10,666 calls (target 99.9%).
  Availability there means *a decision was rendered*, denials included — §9
  makes a deny during an outage correct behaviour, and scoring it as downtime
  would reward failing open. In-process only: no load balancer, network
  partition, disk-exhaustion or OOM coverage, so it is **not** a production
  uptime SLO. Re-run it after touching any fail-open/fail-closed path; its
  first run found a §9 escape the unit tests missed.
- Audit overflow still loses decisions, it just records that it did. The queue is bounded (`AUDIT_QUEUE_MAXSIZE`, default 10k) with `AUDIT_OVERFLOW_POLICY` = `drop_newest` (default) or `drop_oldest`; drops are counted per session and flushed into that session's hash chain as an `audit_gap` marker, so replay shows the hole and still verifies. No spill-to-disk, so a long overload is still permanent loss — FR-AL-01 is auditable under overload, not satisfied by it.

## Measured state (PRD §14.2) — do not overstate

`benchmarks/results/memory_poisoning.md` is the committed baseline. As of the
last run the memory integrity layer measures **33.3% ASR against a < 10%
target**; §14.2 acceptance is NOT met. Residual failures are concentrated in
families no shipped detector matches (`tool_hijack`, `authority_spoof`) —
that gap needs the §6.3 classifier, not more scoring rules.

**That 33.3% is storage, not harm.** `benchmarks/results/memory_poisoning_harm.md`
applies the InjecAgent standard (success = the mediator would have let the goal
through): 0/13 tool cases and 0/22 control-bypass cases are harmful; 1/5 output
cases leak; 8 informational cases have no mediator gate at all. Pessimistic
total **18.8%**. Report both numbers — quoting only the harm figure is moving
the goalposts, quoting only storage overstates a record the control path never
reads. Never count the 8 informational cases as defended; the mediator gates
actions and egress, not beliefs.

The reason 22 cases are inert is load-bearing and measured, not assumed:
authorisation comes from the declarative policy store and **the mediator never
reads agent memory to decide it**, so a record asserting "policy validation has
been disabled" cannot disable it. `tests/unit/test_memory_harm.py` persists
that poison as ACTIVE and asserts forbidden tools are still denied. Any change
that lets memory influence a policy decision breaks §5.2 and that test.

When changing the scorer, thresholds or detectors, re-run the benchmark and
update the committed result. Do not tune weights or add regex patterns against
this corpus: it was written in-house, so that is overfitting, not a result.

**External validation now exists.** `benchmarks/results/injecagent.md` is the
committed baseline for 1054 third-party indirect-injection cases (InjecAgent,
ACL 2024, MIT, vendored). All five §14.2 KPIs PASS — but never quote the
headline without the ablation:

- `no_scanner` is also 0.0%; `no_tool_policy` is **100.0%**. Tool policy is the
  *entire* defence. **The injection scanner detects 0 of 1054 attacks.**
- Do not describe the 0% ASR as evidence the scanner works. It is evidence that
  least agency holds while detection contributes nothing.

**§6.3 is broken in two independent ways, both measured** (details and the
already-rejected fixes are in `benchmarks/README.md`):

1. **Stage 2 is unreachable.** `scan()` runs the classifier only when the regex
   pre-filter scores at or above `SCANNER_ML_GATE_THRESHOLD` (default 0.20);
   992/1054 attacks score exactly 0.0. A mock oracle returning 1.0 is consulted
   on **0 of 1054**. So `SCANNER_BACKEND=llm` buys nothing on the
   `untrusted_data` path without also lowering the gate — it changes which
   classifier runs, not whether it runs. `risky_external` bypasses the gate and
   is always classified, so an LLM backend does work there today.
2. **The classifier is anti-discriminative.** Ungated, it scores attacks at 0.478
   and benign at 0.515 — benign *higher*. Measured: `SCANNER_ML_GATE_THRESHOLD=0.0`
   on InjecAgent catches 19.7% more attacks but takes FPR 0.0% → 23.5% and
   utility 100% → 76.5%, flipping two KPIs to FAIL. Neither fix works alone, so
   the gate default stays at 0.20 until a classifier earns opening it.

Two TF-IDF training approaches on external Apache-2.0 corpora were measured and
rejected (held-out AUC 0.660 and 0.506 — the latter a coin flip). Bag-of-words
cannot represent the discriminating signal, which is syntactic ("is there an
imperative addressed to an assistant in this payload?"). Do not retry that
family. `SCANNER_BACKEND=llm` already ships and is the cheapest untested option.

Any classifier work must train on external data and evaluate against the
in-house corpus as a held-out set, never the reverse.
