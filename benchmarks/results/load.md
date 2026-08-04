# Load and latency report

- Python 3.12.3 on Linux-6.14.0-37-generic-x86_64-with-glibc2.39
- Backing store: `sqlite (throwaway)`
- Run: 5.0s per scenario, concurrency 8, 1.0s warm-up (discarded)

## Throughput and latency

| Scenario | Target | Kind | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|---|---|---|---:|---:|---:|---:|---:|---:|
| `context_benign` | pipeline | fast_path | 7,788 | 0.12 | 0.17 | 0.21 | 92.15 | 0 |
| `context_injection` | pipeline | fast_path | 1,762 | 0.54 | 0.67 | 0.79 | 64.56 | 0 |
| `tool_call_policy` | pipeline | deterministic | 31,366 | 0.03 | 0.04 | 0.05 | 132.07 | 0 |
| `output_redaction` | pipeline | fast_path | 13,494 | 0.07 | 0.11 | 0.13 | 97.60 | 0 |
| `memory_write` | pipeline | db_bound | 60 | 53.93 | 655.12 | 1083.99 | 2089.84 | 0 |
| `context_benign` | http | fast_path | 310 | 23.62 | 30.94 | 97.73 | 107.87 | 0 |
| `context_injection` | http | fast_path | 240 | 30.61 | 41.79 | 107.08 | 118.42 | 0 |
| `tool_call_policy` | http | deterministic | 334 | 22.10 | 28.94 | 92.62 | 100.83 | 0 |
| `output_redaction` | http | fast_path | 318 | 23.08 | 28.92 | 98.19 | 106.08 | 0 |
| `memory_write` | http | db_bound | 26 | 164.82 | 1095.65 | 2511.71 | 3770.72 | 0 |

## NFR acceptance (PRD §8.1, §8.2)

| Scenario | KPI | Measured | Target | Result |
|---|---|---:|---:|---|
| `context_benign` | latency_p50_ms | 0.12 ms | < 120 ms | PASS |
| `context_benign` | latency_p95_ms | 0.17 ms | < 400 ms | PASS |
| `context_benign` | error_rate | 0.00% | 0% | PASS |
| `context_injection` | latency_p50_ms | 0.54 ms | < 120 ms | PASS |
| `context_injection` | latency_p95_ms | 0.67 ms | < 400 ms | PASS |
| `context_injection` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | latency_p50_ms | 0.03 ms | < 120 ms | PASS |
| `tool_call_policy` | latency_p95_ms | 0.04 ms | < 400 ms | PASS |
| `tool_call_policy` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | policy_p95_ms | 0.04 ms | < 10 ms | PASS — NFR-PERF-03 deterministic path |
| `output_redaction` | latency_p50_ms | 0.07 ms | < 120 ms | PASS |
| `output_redaction` | latency_p95_ms | 0.11 ms | < 400 ms | PASS |
| `output_redaction` | error_rate | 0.00% | 0% | PASS |
| `memory_write` | latency_p50_ms | 53.93 ms | < 120 ms | N/A — not on the §8.1 fast path |
| `memory_write` | latency_p95_ms | 655.12 ms | < 400 ms | N/A — not on the §8.1 fast path |
| `memory_write` | error_rate | 0.00% | 0% | PASS |
| `context_benign` | latency_p50_ms | 23.62 ms | < 120 ms | PASS |
| `context_benign` | latency_p95_ms | 30.94 ms | < 400 ms | PASS |
| `context_benign` | error_rate | 0.00% | 0% | PASS |
| `context_injection` | latency_p50_ms | 30.61 ms | < 120 ms | PASS |
| `context_injection` | latency_p95_ms | 41.79 ms | < 400 ms | PASS |
| `context_injection` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | latency_p50_ms | 22.10 ms | < 120 ms | PASS |
| `tool_call_policy` | latency_p95_ms | 28.94 ms | < 400 ms | PASS |
| `tool_call_policy` | error_rate | 0.00% | 0% | PASS |
| `tool_call_policy` | policy_p95_ms | 28.94 ms | < 10 ms | N/A — measured over HTTP; NFR-PERF-03 scopes this to the engine — use --target pipeline |
| `output_redaction` | latency_p50_ms | 23.08 ms | < 120 ms | PASS |
| `output_redaction` | latency_p95_ms | 28.92 ms | < 400 ms | PASS |
| `output_redaction` | error_rate | 0.00% | 0% | PASS |
| `memory_write` | latency_p50_ms | 164.82 ms | < 120 ms | N/A — not on the §8.1 fast path |
| `memory_write` | latency_p95_ms | 1095.65 ms | < 400 ms | N/A — not on the §8.1 fast path |
| `memory_write` | error_rate | 0.00% | 0% | PASS |

## NFR-SCAL-01 — sustained throughput per instance

Best sustained fast-path throughput over HTTP: **334 req/s** (`tool_call_policy`) against a target of ≥ 100 req/s — **PASS**.

## NFR-PERF-04 — audit off the request path

Enqueue is `put_nowait` and never awaited, so audit adds no measurable latency to the request path — the requirement is met as written.

### Audit write throughput — PASS

The background writer was measured saturated at **2,809 events/s** (SQLite). Every mediated call emits at least one audit event and FR-AL-01 requires all of them to be recorded, so this bounds the sustainable request rate, not just an internal detail. Against NFR-SCAL-01's 100 req/s that is **28.1x** — and a single agent turn spanning context, tool call, memory write and output emits four events, putting the sustainable turn rate near **702/s**.

The background writer coalesces queued events into one transaction per batch (`AUDIT_BATCH_MAX`), re-reading each session's chain tail under a row lock inside that transaction. Setting `AUDIT_BATCH_MAX=1` restores per-event writes, which measured ~140 events/s and made audit the binding constraint on throughput.

This figure is measured across **50 concurrent sessions**, which is the pessimistic case: a batch still needs one locked tail read per distinct session it touches, so audit throughput falls as session fan-out rises and rises toward ~9,000 events/s for single-session traffic. Sizing should use the multi-session number. PostgreSQL is untested here and would change the constant, not the shape.

| Scenario | Events queued at end of run |
|---|---:|
| `context_benign` | 38,820 |
| `context_injection` | 8,808 |
| `tool_call_policy` | 156,834 |
| `output_redaction` | 67,486 |
| `context_benign` | 8 |
| `context_injection` | 8 |
| `tool_call_policy` | 24 |
| `output_redaction` | 25 |

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
