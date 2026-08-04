# Load and latency report

- Python 3.12.3 on Linux-6.14.0-37-generic-x86_64-with-glibc2.39
- Backing store: `sqlite (throwaway)`
- Run: 5.0s per scenario, concurrency 8, 1.0s warm-up (discarded)

## Throughput and latency

| Scenario | Target | Kind | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|---|---|---|---:|---:|---:|---:|---:|---:|
| `context_benign` | pipeline | fast_path | 4,871 | 0.17 | 0.31 | 0.38 | 138.74 | 0 |
| `context_injection` | pipeline | fast_path | 921 | 0.87 | 1.96 | 2.74 | 5.24 | 0 |
| `tool_call_policy` | pipeline | deterministic | 20,040 | 0.04 | 0.07 | 0.10 | 143.77 | 0 |
| `output_redaction` | pipeline | fast_path | 11,243 | 0.08 | 0.13 | 0.16 | 115.17 | 0 |
| `memory_write` | pipeline | db_bound | 40 | 103.22 | 583.98 | 1668.25 | 3129.95 | 0 |
| `context_benign` | http | fast_path | 221 | 31.91 | 52.12 | 135.61 | 139.26 | 0 |
| `context_injection` | http | fast_path | 187 | 39.71 | 59.07 | 125.14 | 143.27 | 0 |
| `tool_call_policy` | http | deterministic | 246 | 28.20 | 56.67 | 118.10 | 129.68 | 0 |
| `output_redaction` | http | fast_path | 246 | 28.95 | 49.67 | 122.04 | 145.17 | 0 |
| `memory_write` | http | db_bound | 23 | 185.49 | 1457.55 | 2131.94 | 2132.22 | 0 |

## NFR acceptance (PRD §8.1, §8.2)

| Scenario | KPI | Measured | Target | Result |
|---|---|---:|---:|---|
| `context_benign` | latency_p50_ms | 0.17 ms | < 120 ms | PASS |
| `context_benign` | latency_p95_ms | 0.31 ms | < 400 ms | PASS |
| `context_benign` | error_rate | 0.00% | 0% | PASS |
| `context_injection` | latency_p50_ms | 0.87 ms | < 120 ms | PASS |
| `context_injection` | latency_p95_ms | 1.96 ms | < 400 ms | PASS |
| `context_injection` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | latency_p50_ms | 0.04 ms | < 120 ms | PASS |
| `tool_call_policy` | latency_p95_ms | 0.07 ms | < 400 ms | PASS |
| `tool_call_policy` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | policy_p95_ms | 0.07 ms | < 10 ms | PASS — NFR-PERF-03 deterministic path |
| `output_redaction` | latency_p50_ms | 0.08 ms | < 120 ms | PASS |
| `output_redaction` | latency_p95_ms | 0.13 ms | < 400 ms | PASS |
| `output_redaction` | error_rate | 0.00% | 0% | PASS |
| `memory_write` | latency_p50_ms | 103.22 ms | < 120 ms | N/A — not on the §8.1 fast path |
| `memory_write` | latency_p95_ms | 583.98 ms | < 400 ms | N/A — not on the §8.1 fast path |
| `memory_write` | error_rate | 0.00% | 0% | PASS |
| `context_benign` | latency_p50_ms | 31.91 ms | < 120 ms | PASS |
| `context_benign` | latency_p95_ms | 52.12 ms | < 400 ms | PASS |
| `context_benign` | error_rate | 0.00% | 0% | PASS |
| `context_injection` | latency_p50_ms | 39.71 ms | < 120 ms | PASS |
| `context_injection` | latency_p95_ms | 59.07 ms | < 400 ms | PASS |
| `context_injection` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | latency_p50_ms | 28.20 ms | < 120 ms | PASS |
| `tool_call_policy` | latency_p95_ms | 56.67 ms | < 400 ms | PASS |
| `tool_call_policy` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | policy_p95_ms | 56.67 ms | < 10 ms | N/A — measured over HTTP; NFR-PERF-03 scopes this to the engine — use --target pipeline |
| `output_redaction` | latency_p50_ms | 28.95 ms | < 120 ms | PASS |
| `output_redaction` | latency_p95_ms | 49.67 ms | < 400 ms | PASS |
| `output_redaction` | error_rate | 0.00% | 0% | PASS |
| `memory_write` | latency_p50_ms | 185.49 ms | < 120 ms | N/A — not on the §8.1 fast path |
| `memory_write` | latency_p95_ms | 1457.55 ms | < 400 ms | N/A — not on the §8.1 fast path |
| `memory_write` | error_rate | 0.00% | 0% | PASS |

## NFR-SCAL-01 — sustained throughput per instance

Best sustained fast-path throughput over HTTP: **246 req/s** (`output_redaction`) against a target of ≥ 100 req/s — **PASS**.

## NFR-PERF-04 — audit off the request path

Enqueue is `put_nowait` and never awaited, so audit adds no measurable latency to the request path — the requirement is met as written.

### Audit write throughput is the binding constraint — FAIL

The background writer was measured saturated at **53 events/s** (SQLite). Every mediated call emits at least one audit event and FR-AL-01 requires all of them to be recorded, so this is a ceiling on sustainable request rate, not just an internal detail. Against NFR-SCAL-01's 100 req/s that is only **0.5x** — and a single agent turn spanning context, tool call, memory write and output emits four events, which would put the effective sustainable turn rate near **13/s**.

Cause is structural rather than SQLite being slow: `AuditRepository.append_chained` runs one `SELECT` for the previous hash plus one `INSERT`, in its own transaction, per event. The hash chain forces the read-then-write ordering, but not the per-event transaction — batching consecutive events for a session into one transaction, or maintaining the chain head in memory per writer, would both cut this substantially. PostgreSQL is untested here and would change the constant, not the shape.

| Scenario | Events queued at end of run |
|---|---:|
| `context_benign` | 24,361 |
| `context_injection` | 4,604 |
| `tool_call_policy` | 100,206 |
| `output_redaction` | 56,220 |
| `memory_write` | 170 |
| `context_benign` | 1,049 |
| `context_injection` | 878 |
| `tool_call_policy` | 1,159 |
| `output_redaction` | 1,156 |
| `memory_write` | 106 |

The queue is unbounded (`asyncio.Queue()` with no maxsize), so whenever offered load exceeds writer throughput the cost is **deferred into memory rather than removed**, and queued decisions are lost on abrupt shutdown. A maxsize plus an explicit drop-or-spill policy would bound that — this matters for FR-AL-01 (every decision recorded) more than for latency.

## How to read these numbers

**In-process, single event loop.** The `http` target drives the ASGI app
through an in-memory transport, so it excludes kernel networking, TLS and the
uvicorn worker pool. Python's event loop is single-threaded and mediation is
CPU-bound, so this measures **one worker's** capacity — which is what
NFR-SCAL-01 ("per instance") asks for, but a deployed instance runs several
uvicorn workers and would scale roughly with that count.

**SQLite backing store.** Database-bound scenarios were measured against
SQLite, not the PostgreSQL of a production deployment. Their absolute numbers
are indicative only; the fast-path scenarios touch no database and are
unaffected.

**Throughput varies roughly ±25% run to run.** The audit writer shares the
single event loop with the requests being measured, and the host is not
isolated, so HTTP throughput figures should be read as an order of magnitude
rather than a precise number. The NFR-SCAL-01 verdict is robust to that
spread — the low end of the observed range still clears 100 req/s — but a
change of less than about a third between runs is noise, not a regression.

**This is not a soak test.** NFR-AVAIL-01 (99.9% availability) requires
fault injection and a long-running soak, neither of which exists yet. Nothing
here should be read as evidence for it.
