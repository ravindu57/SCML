# TrustMediator evaluation harness (PRD §14)

Implements the P3 "Evaluation" phase: KPI measurement against the §14.2
targets and the per-module ablation study of §14.3.

## Running

```bash
# Full grid, report to stdout
.venv/bin/python -m benchmarks.cli --testbed memory_poisoning

# Save markdown + JSON
.venv/bin/python -m benchmarks.cli --testbed memory_poisoning --format both --out benchmarks/results

# One configuration only
.venv/bin/python -m benchmarks.cli --config full_defence
```

The CLI pins its own environment (test mode, throwaway SQLite store, scanner
shadow mode off) before importing `trust_mediator`, so it runs correctly
regardless of what the repo `.env` contains and never touches the application
database. Exit code is non-zero when the `full_defence` run misses an
applicable §14.2 target.

Latest committed results: [`results/memory_poisoning.md`](results/memory_poisoning.md).

## Load and latency (PRD §8.1, §8.2)

Separate from the security testbeds — it scores throughput against a clock
rather than decisions against attacks.

```bash
python -m benchmarks.load                       # both targets
python -m benchmarks.load --target pipeline     # mediator cost only
python -m benchmarks.load --target http --duration 10 --concurrency 32
```

Latest committed results: [`results/load.md`](results/load.md).

| NFR | Target | Measured | |
|---|---|---|---|
| NFR-PERF-01 fast-path latency | p50 < 120 ms, p95 < 400 ms | p50 32 ms, p95 52 ms (HTTP) | ✅ |
| NFR-PERF-03 policy decision | p95 < 10 ms | 0.07 ms (engine) | ✅ |
| NFR-SCAL-01 throughput | ≥ 100 req/s | 246 req/s (HTTP) | ✅ |
| NFR-PERF-04 audit off path | 0 ms on path | enqueue never awaited | ✅ |
| NFR-AVAIL-01 availability | ≥ 99.9% | not measured — needs a soak | — |

Two targets, because the PRD scopes its budgets differently: `pipeline` calls
`MediationPipeline` directly and answers NFR-PERF-01/03 ("added latency per
mediated call", "policy engine decision latency"), while `http` drives the ASGI
app and answers NFR-SCAL-01 ("sustained mediated requests"). Quoting the
pipeline figure as throughput would overstate capacity by ~100x, so the harness
reports NFR-SCAL-01 as *not measured* unless an HTTP run is present.

### The finding: audit write throughput is the binding constraint

The request path comfortably beats its targets, but the audit writer saturates
at **~140 events/s** on SQLite. Every mediated call emits at least one event
and FR-AL-01 requires all of them to be recorded, so sustained operation above
that rate grows an unbounded in-memory queue and loses decisions on shutdown —
it does not degrade latency, which is why this never showed up before.

The cause is structural, not SQLite being slow: `AuditRepository.append_chained`
runs a `SELECT` for the previous hash plus an `INSERT` in its own transaction,
per event. The hash chain forces read-then-write ordering; it does not force a
transaction per event. Batching a session's consecutive events, or keeping the
chain head in memory per writer, would both cut this materially.

## Structure

| Path | Role |
|---|---|
| `harness/case.py` | `AttackCase` / `BenignCase` / `CaseOutcome` structures |
| `harness/ablation.py` | Ablation axes + null layer implementations |
| `harness/metrics.py` | §14.2 KPI computation |
| `harness/runner.py` | Grid execution, environment capture |
| `harness/report.py` | Markdown + JSON rendering |
| `testbeds/memory_poisoning/` | Corpus and run logic for the §6.5 layer |

Adding AgentDojo or InjecAgent means writing a class satisfying the `Testbed`
protocol (`name`, `supported_axes`, `asr_kpi`, `async run()`); the harness,
metrics and reporting are shared.

## Methodology

**Ablation by substitution.** A disabled layer is replaced with a null
implementation satisfying the same interface. Nothing in `trust_mediator/`
branches on whether it is being benchmarked — the code path under test is the
production one.

**Per-case isolation.** Every case runs in its own `agent_id` namespace,
re-seeded with the same five trusted baseline facts. Cases cannot influence
one another, so an ASR is never an artifact of case ordering.

**Success is defined by agent-observable effect**, not internal verdicts:

| | Attack succeeds when | Benign case is a false positive when |
|---|---|---|
| Write path | the poisoned record ends up `ACTIVE` (readable, able to steer future sessions) | a legitimate memory is anything other than persisted |
| Read path | an already-`ACTIVE` poisoned record is served back as verified (FR-MI-04) | — |

Quarantine and reject both count as blocked: either way the agent cannot read
the record.

**Honest axis reporting.** A testbed declares which ablation axes it actually
varies. Trust routing and tool policy do not sit on the memory write path, so
the memory testbed reports them `N/A` rather than crediting them.

**The benign corpus is adversarial on purpose.** Twelve of the forty benign
cases are legitimate user preferences phrased as standing instructions
("always use metric units"). Real assistants store these, and a defence that
blocks them destroys utility. They carry `TRUSTED_INSTRUCTION` because that is
their true provenance (§5.2) — the authenticated user said them. A corpus
without such cases would make the FPR < 3% target trivial to pass.

## Attack corpus provenance

Families derive from the published patterns cited in PRD §18:

| Family | Cases | Derived from |
|---|---:|---|
| `instruction_override` | 5 + 1 read | [7] Memory Poisoning Attack and Defense |
| `persistent_directive` | 5 + 1 read | [4] AgentPoison |
| `tool_hijack` | 5 + 1 read | [8] MemMorph |
| `backdoor_trigger` | 5 + 1 read | [4] AgentPoison |
| `fact_replacement` | 5 + 1 read | [7] Memory Poisoning Attack and Defense |
| `exfiltration_directive` | 5 + 1 read | [8] MemMorph |
| `authority_spoof` | 5 + 1 read | [7] Memory Poisoning Attack and Defense |
| `obfuscated_injection` | 5 + 1 read | [3] LlamaFirewall |

48 attack cases, 40 benign cases.

## Findings so far

The first run measured 47.9% ASR and exposed two structural defects, both
since fixed:

| Defect | Evidence | Fix |
|---|---|---|
| The read path applied a weaker standard than the write path — it withheld only on a block/escalate scanner verdict, so poison scoring below that was served back to the agent even though an identical *write* would have been refused | read-path ASR 88% | `verify_read` now runs the full write gauntlet (`_evaluate`); `MEMORY_RESCAN_ON_READ` now defaults on, since FR-MI-04 is a Must |
| Contradiction with trusted memory was a weighted term worth ~0.12 of the composite, so a *detected* fact-replacement attack still cleared the persist threshold | `fact_replacement` ASR 83% despite contradiction scores of 0.30–0.47 | contradiction is now a hard gate → quarantine for review, never silent persist |

Result: **47.9% → 33.3% ASR**, read path 88% → 38%, `fact_replacement`
83% → 17%, with FPR unchanged at 0.0% and utility at 100%.

Still short of the < 10% target. The residual failures are concentrated in
`tool_hijack` (83%) and `authority_spoof` (67%) — plainly worded poisoned
memories that match no shipped detector at all (scanner 0.00, instruction
patterns 0.00). That is a detector-coverage problem, and the honest fix is
the trained classifier of §6.3, not more hand-written rules. See the caveat
below.

## ⚠️ Reading the results honestly

Two caveats that matter for any claim made from these numbers.

**1. The corpus and the defence share an author.** Tuning thresholds or adding
detector patterns until this testbed passes would be overfitting to a corpus
written in-house, and the resulting ASR would not be a research result. Any
tuning driven by these findings should be validated on a corpus the tuner did
not write — the external AgentDojo and InjecAgent suites exist precisely for
this, and are not yet implemented.

**2. The scanner is the heuristic pre-filter only.** `SCANNER_BACKEND=onnx`
still falls back to heuristics; no trained DeBERTa model ships. Every ASR here
therefore measures regex + TF-IDF detection, not the scanner the PRD
specifies in §6.3/§11. Expect these numbers to move substantially once a real
classifier lands.

## Not yet implemented

Do not cite these as existing:

- AgentDojo testbed (§14.1)
- InjecAgent testbed (§14.1)
- Load/soak testing for NFR-SCAL-01 (≥ 100 req/s) and NFR-AVAIL-01 (99.9%)
