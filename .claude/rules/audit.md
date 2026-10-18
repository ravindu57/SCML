---
paths:
  - "trust_mediator/modules/audit_log/**"
  - "trust_mediator/db/**"
  - "trust_mediator/core/pipeline.py"
  - "trust_mediator/api/admin_audit.py"
  - "trust_mediator/api/routers/audit.py"
  - "trust_mediator/observability.py"
---

# Audit log, hash chain, tracing (FR-AL-01, NFR-PERF-04, NFR-OBS-01)

- **Audit everything:** every mediation decision emits an `AuditEvent` through `AuditLogger` (SHA-256 hash chain). New decision points must log. So do control-plane actions, via `api/admin_audit.record_admin_action` into the tenant's `#control-plane::<tenant>` chain (admin-only replay at `GET /v1/audit/control-plane`); a new admin route must record itself. The hash covers every field from `hash_version` 2 on; when you add a field to `AuditEvent`, add it to `compute_hash` under a *new* version, never by changing v2, or every stored v2 chain stops verifying. Public `MediationPipeline.process_*` methods are audit wrappers: implementations live in `_process_*`, and an unexpected exception is recorded as `pipeline_exception` before it propagates. A failed audit write leaves an `audit_gap` marker (`cause: write_failed`), like an overflow.

- Audit fan-out: Kafka (`modules/audit_log/kafka_forwarder.py`, optional `[kafka]` extra) + SIEM webhook; DB hash chain is authoritative.

- Audit chain integrity is enforced transactionally in `AuditRepository.append_chained` / `append_chained_batch` (row lock + unique (session_id, seq_no)); never reintroduce per-process chain state in AuditLogger. The batch variant re-reads each session's tail under the lock inside its own transaction, so it is safe across workers — chaining in memory is only valid *within* one locked transaction.
- `AuditLogger.log()` must never block or await — it is on the request path (NFR-PERF-04). Overflow drops and records; it does not apply back-pressure. `log_async()` is the awaiting variant, for off-path callers only. Eviction under `drop_oldest` pairs every `get_nowait()` with a `task_done()`, or `stop()` hangs on `join()`.
- The audit writer coalesces queued events into one transaction per batch (`AUDIT_BATCH_MAX`, default 128). Per-event writes measured ~140 events/s and made audit the throughput ceiling; batching lifts it to ~2,800/s across 50 sessions. Throughput falls as session fan-out rises (one locked tail read per session per batch). `AUDIT_BATCH_MAX=1` restores the old behaviour.

- Tracing: `trust_mediator/observability.py` (NFR-OBS-01). Spans wrap every pipeline decision point. Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set; export needs the `[otlp]` extra. **Span attributes carry decisions/labels/scores only — never mediated content**, since spans leave the process for a collector the mediator does not control. `test_spans_never_carry_mediated_content` enforces this.

- Audit overflow still loses decisions, it just records that it did. The queue is bounded (`AUDIT_QUEUE_MAXSIZE`, default 10k) with `AUDIT_OVERFLOW_POLICY` = `drop_newest` (default) or `drop_oldest`; drops are counted per session and flushed into that session's hash chain as an `audit_gap` marker, so replay shows the hole and still verifies. No spill-to-disk, so a long overload is still permanent loss — FR-AL-01 is auditable under overload, not satisfied by it.
