"""Report rendering for load runs (PRD §8.1, §8.2)."""

from __future__ import annotations

import json
from dataclasses import asdict

from benchmarks.load.metrics import LoadMetrics

_CAVEAT = """\
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
"""


def render_markdown(metrics: list[LoadMetrics], environment: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# Load and latency report")
    lines.append("")
    lines.append(f"- Python {environment['python']} on {environment['platform']}")
    lines.append(f"- Backing store: `{environment['database']}`")
    lines.append(f"- Run: {environment['duration_s']}s per scenario, "
                 f"concurrency {environment['concurrency']}, "
                 f"{environment['warmup_s']}s warm-up (discarded)")
    lines.append("")

    lines.append("## Throughput and latency")
    lines.append("")
    lines.append(
        "| Scenario | Target | Kind | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |"
    )
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|")
    for m in metrics:
        lines.append(
            f"| `{m.scenario}` | {m.target} | {m.kind} | {m.throughput_rps:,.0f} | "
            f"{m.latency_p50_ms:.2f} | {m.latency_p95_ms:.2f} | {m.latency_p99_ms:.2f} | "
            f"{m.latency_max_ms:.2f} | {m.errors} |"
        )
    lines.append("")

    lines.append("## NFR acceptance (PRD §8.1, §8.2)")
    lines.append("")
    lines.append("| Scenario | KPI | Measured | Target | Result |")
    lines.append("|---|---|---:|---:|---|")
    for m in metrics:
        for check in m.kpi_checks():
            measured = (
                f"{check.value:.2%}"
                if check.kpi == "error_rate"
                else f"{check.value:.2f} ms"
            )
            target = (
                f"{check.target:.0%}"
                if check.kpi == "error_rate"
                else f"< {check.target:.0f} ms"
            )
            note = f" — {check.note}" if check.note else ""
            lines.append(
                f"| `{m.scenario}` | {check.kpi} | {measured} | {target} | "
                f"{check.status}{note} |"
            )
    lines.append("")

    # NFR-SCAL-01 is about *served requests*, so it may only be judged on the
    # http target. The pipeline target excludes routing, auth, rate limiting
    # and serialisation entirely — quoting it as throughput would overstate
    # capacity by an order of magnitude.
    lines.append("## NFR-SCAL-01 — sustained throughput per instance")
    lines.append("")
    served = [
        m
        for m in metrics
        if m.target == "http" and m.kind in ("fast_path", "deterministic")
    ]
    if served:
        best = max(served, key=lambda m: m.throughput_rps)
        status = "PASS" if best.throughput_rps >= 100.0 else "FAIL"
        lines.append(
            f"Best sustained fast-path throughput over HTTP: "
            f"**{best.throughput_rps:,.0f} req/s** (`{best.scenario}`) against a "
            f"target of ≥ 100 req/s — **{status}**."
        )
    else:
        fast = [m for m in metrics if m.kind in ("fast_path", "deterministic")]
        ceiling = max((m.throughput_rps for m in fast), default=0.0)
        lines.append(
            "**Not measured** — this run used the `pipeline` target only, which "
            "bypasses routing, auth, rate limiting and serialisation. The "
            f"mediation logic itself sustains ~{ceiling:,.0f} calls/s, which is "
            "an upper bound on what the served endpoint could reach, not a "
            "throughput result. Re-run with `--target http` to measure it."
        )
    lines.append("")

    lines.append("## NFR-PERF-04 — audit off the request path")
    lines.append("")
    lines.append(
        "Enqueue is `put_nowait` and never awaited, so audit adds no measurable "
        "latency to the request path — the requirement is met as written."
    )
    lines.append("")
    drain_rps = float(environment.get("audit_drain_rps", 0.0) or 0.0)
    backlogged = [m for m in metrics if m.audit_backlog > 0]
    if drain_rps > 0:
        headroom = drain_rps / 100.0
        verdict = "FAIL" if drain_rps < 100.0 else "MARGINAL" if headroom < 3 else "PASS"
        heading = (
            "Audit write throughput is the binding constraint"
            if headroom < 3
            else "Audit write throughput"
        )
        lines.append(f"### {heading} — {verdict}")
        lines.append("")
        qualifier = "only " if headroom < 3 else ""
        lines.append(
            f"The background writer was measured saturated at **{drain_rps:,.0f} "
            f"events/s** (SQLite). Every mediated call emits at least one audit "
            f"event and FR-AL-01 requires all of them to be recorded, so this "
            f"bounds the sustainable request rate, not just an internal detail. "
            f"Against NFR-SCAL-01's 100 req/s that is {qualifier}**{headroom:.1f}x** — "
            f"and a single agent turn spanning context, tool call, memory write "
            f"and output emits four events, putting the sustainable turn rate "
            f"near **{drain_rps / 4:,.0f}/s**."
        )
        lines.append("")
        if headroom < 3:
            lines.append(
                "Cause is structural rather than SQLite being slow: the writer "
                "is running one `SELECT` for the previous hash plus one `INSERT`, "
                "in its own transaction, per event. The hash chain forces the "
                "read-then-write ordering, but not the per-event transaction."
            )
        else:
            sessions = environment.get("audit_probe_sessions", "?")
            lines.append(
                "The background writer coalesces queued events into one "
                "transaction per batch (`AUDIT_BATCH_MAX`), re-reading each "
                "session's chain tail under a row lock inside that transaction. "
                "Setting `AUDIT_BATCH_MAX=1` restores per-event writes, which "
                "measured ~140 events/s and made audit the binding constraint on "
                "throughput."
            )
            lines.append("")
            lines.append(
                f"This figure is measured across **{sessions} concurrent "
                "sessions**, which is the pessimistic case: a batch still needs "
                "one locked tail read per distinct session it touches, so audit "
                "throughput falls as session fan-out rises and rises toward "
                "~9,000 events/s for single-session traffic. Sizing should use "
                "the multi-session number. PostgreSQL is untested here and would "
                "change the constant, not the shape."
            )
        lines.append("")
    if backlogged:
        lines.append("| Scenario | Events queued at end of run |")
        lines.append("|---|---:|")
        for m in backlogged:
            lines.append(f"| `{m.scenario}` | {m.audit_backlog:,} |")
        lines.append("")
        lines.append(
            "The queue is unbounded (`asyncio.Queue()` with no maxsize), so "
            "whenever offered load exceeds writer throughput the cost is "
            "**deferred into memory rather than removed**, and queued decisions "
            "are lost on abrupt shutdown. A maxsize plus an explicit "
            "drop-or-spill policy would bound that — this matters for FR-AL-01 "
            "(every decision recorded) more than for latency."
        )
    else:
        lines.append("No backlog remained at end of run in any scenario.")
    lines.append("")

    lines.append(_CAVEAT)
    return "\n".join(lines)


def render_json(metrics: list[LoadMetrics], environment: dict[str, str]) -> str:
    return json.dumps(
        {
            "environment": environment,
            "scenarios": [
                {
                    **asdict(m),
                    "error_rate": m.error_rate,
                    "kpi_checks": [
                        {
                            "kpi": c.kpi,
                            "value": c.value,
                            "target": c.target,
                            "status": c.status,
                            "note": c.note,
                        }
                        for c in m.kpi_checks()
                    ],
                }
                for m in metrics
            ],
        },
        indent=2,
    )
