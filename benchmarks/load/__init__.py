"""
Load and latency measurement (PRD §8.1, §8.2).

Measures the NFRs that were previously asserted but never measured:

  NFR-PERF-01  added latency on the fast path      p50 < 120 ms, p95 < 400 ms
  NFR-PERF-03  policy engine decision latency      p95 < 10 ms
  NFR-PERF-04  audit logging off the request path  async, 0 ms on path
  NFR-SCAL-01  sustained mediated requests         >= 100 req/s per instance

Kept separate from `benchmarks/testbeds/` because the unit of measurement is
different: a security testbed scores decisions against attacks, this scores
throughput and latency against a clock. Both share `percentile` and `KpiCheck`
so a KPI table means the same thing in either report.

Usage:
    python -m benchmarks.load --target pipeline
    python -m benchmarks.load --target http --duration 10 --concurrency 32

**This module deliberately re-exports nothing.** `python -m benchmarks.load`
imports this file before `__main__.main()` can pin DATABASE_URL and friends,
and `trust_mediator.db.base` builds its engine at import time from settings.
An `from benchmarks.load.runner import ...` here would therefore drag
`trust_mediator.config` in too early and the benchmark would silently run
against the application's own database in dev mode. Import from the
submodules directly instead.
"""
