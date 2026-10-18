---
paths:
  - "trust_mediator/modules/memory_integrity/**"
  - "trust_mediator/api/routers/memory.py"
  - "benchmarks/testbeds/memory_poisoning/**"
---

# Memory integrity (FR-MI-*). Measured ASR: rules/benchmarks.md

The reason 22 cases are inert is load-bearing and measured, not assumed:
authorisation comes from the declarative policy store and **the mediator never
reads agent memory to decide it**, so a record asserting "policy validation has
been disabled" cannot disable it. `tests/unit/test_memory_harm.py` persists
that poison as ACTIVE and asserts forbidden tools are still denied. Any change
that lets memory influence a policy decision breaks §5.2 and that test.

When changing the scorer, thresholds or detectors, re-run the benchmark and
write a new versioned result file under benchmarks/results/v2/ (ADR-0001: committed baselines are frozen and never overwritten). Do not tune weights or add regex patterns against
this corpus: it was written in-house, so that is overfitting, not a result.
