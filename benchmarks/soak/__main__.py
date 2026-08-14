"""
Soak CLI (PRD §8.3, NFR-AVAIL-01).

    python -m benchmarks.soak --duration 60
    python -m benchmarks.soak --out benchmarks/results --format both

Runs against its own throwaway SQLite database. Environment is pinned before
any `trust_mediator` import, because `trust_mediator.db.base` builds its engine
at import time from settings — importing first would point the soak at the
application store and inject faults into it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path


def _configure_environment(db_path: Path) -> None:
    """Mirror the documented local invocation; see benchmarks/cli.py."""
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["TRUST_MEDIATOR_ENV"] = "test"
    os.environ["REDIS_URL"] = ""
    os.environ["TRUST_MEDIATOR_API_KEYS"] = ""
    # Shadow mode would downgrade every scanner verdict to a no-op, so a
    # "decision" would be rendered no matter how broken the scanner was —
    # availability would look perfect precisely when it was not.
    os.environ["SCANNER_SHADOW_MODE"] = "false"


def _quiet_logging() -> None:
    import structlog

    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR)
    )


# ── Reporting ─────────────────────────────────────────────────────────────────


def _summarise(result) -> dict:
    """
    Aggregate outcomes into the numbers §8.3 asks for.

    Availability is computed over *every* call, healthy and faulted alike,
    because that is what an operator experiences. The per-phase breakdown is
    reported alongside so a single bad fault window cannot hide inside a
    healthy average.
    """
    outcomes = result.outcomes
    total = len(outcomes)
    decided = sum(1 for o in outcomes if o.decided)

    by_phase: dict[str, dict] = {}
    for window in result.windows:
        row = by_phase.setdefault(
            window.phase, {"calls": 0, "decided": 0, "errors": {}, "verdicts": {}}
        )
        for o in window.outcomes:
            row["calls"] += 1
            if o.decided:
                row["decided"] += 1
                row["verdicts"][o.verdict] = row["verdicts"].get(o.verdict, 0) + 1
            else:
                key = o.error.split(":")[0]
                row["errors"][key] = row["errors"].get(key, 0) + 1

    for row in by_phase.values():
        row["availability"] = row["decided"] / row["calls"] if row["calls"] else 0.0

    latencies = sorted(o.elapsed_ms for o in outcomes if o.decided)

    def pct(p: float) -> float:
        if not latencies:
            return 0.0
        i = max(0, min(len(latencies) - 1, int(p / 100.0 * len(latencies)) - 1))
        return round(latencies[i], 3)

    return {
        "duration_s": round(result.duration_s, 2),
        "total_calls": total,
        "decided": decided,
        "availability": decided / total if total else 0.0,
        "target": 0.999,
        "met": (decided / total if total else 0.0) >= 0.999,
        "latency_p50_ms": pct(50),
        "latency_p95_ms": pct(95),
        "by_phase": by_phase,
        "recovery_times_s": result.recovery_times_s,
    }


def _render_markdown(summary: dict, environment: dict) -> str:
    a = summary["availability"]
    lines = [
        "# Soak and fault injection — NFR-AVAIL-01",
        "",
        f"- Duration: `{summary['duration_s']}s`",
        f"- Python {environment['python']} on {environment['platform']}",
        "",
        "## What is being measured",
        "",
        "Availability here is **the caller received a decision**, including a",
        "denial. §9 requires a mediator that cannot verify a tool call to deny",
        "it, so a deny during a database outage is correct behaviour, not",
        "downtime — counting it as downtime would reward a mediator that failed",
        "open. A call counts as unavailable only when an exception escaped or",
        "the call timed out.",
        "",
        "## Headline",
        "",
        "| Metric | Measured | Target | Result |",
        "|---|---:|---:|---|",
        f"| Availability (NFR-AVAIL-01) | {a:.3%} | ≥ 99.9% | "
        f"{'PASS' if summary['met'] else 'FAIL'} |",
        f"| Calls | {summary['total_calls']} | — | |",
        f"| Decisions rendered | {summary['decided']} | — | |",
        f"| Latency p50 | {summary['latency_p50_ms']} ms | — | |",
        f"| Latency p95 | {summary['latency_p95_ms']} ms | < 400 ms | "
        f"{'PASS' if summary['latency_p95_ms'] < 400 else 'FAIL'} |",
        "",
        "## Per-phase breakdown",
        "",
        "| Phase | Calls | Availability | Verdicts | Escaped errors |",
        "|---|---:|---:|---|---|",
    ]
    for phase, row in summary["by_phase"].items():
        verdicts = ", ".join(f"{k}={v}" for k, v in sorted(row["verdicts"].items())) or "—"
        errors = ", ".join(f"{k}={v}" for k, v in sorted(row["errors"].items())) or "none"
        lines.append(
            f"| `{phase}` | {row['calls']} | {row['availability']:.2%} | {verdicts} | {errors} |"
        )

    lines += ["", "## Recovery after each fault cleared", "",
              "| Fault | Seconds to first decision |", "|---|---:|"]
    for fault, secs in summary["recovery_times_s"].items():
        lines.append(f"| `{fault}` | {'never' if secs == float('inf') else secs} |")

    lines += [
        "",
        "## Reading this honestly",
        "",
        "Faults are injected into a live in-process pipeline, so this measures",
        "the mediator's own fault handling — not the availability of a deployed",
        "service behind a load balancer, and not network partitions, disk",
        "exhaustion or OOM. A passing number here means the data plane keeps",
        "rendering decisions when a dependency breaks; it is not a production",
        "uptime SLO and must not be quoted as one.",
        "",
    ]
    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────────────────────


async def _run(args: argparse.Namespace) -> int:
    import platform

    from benchmarks.soak.faults import ALL_FAULTS, get_fault
    from benchmarks.soak.runner import SoakRunner
    from trust_mediator.core.pipeline import MediationPipeline
    from trust_mediator.db.base import create_all_tables

    await create_all_tables()

    faults = [get_fault(n) for n in args.fault] if args.fault else ALL_FAULTS
    # The duration is split across every window: one healthy window per fault,
    # plus a leading one. Dividing keeps --duration meaning what it says.
    window_s = max(1.0, args.duration / (2 * len(faults) + 1))

    pipeline = MediationPipeline()
    await pipeline.start() if hasattr(pipeline, "start") else None
    try:
        runner = SoakRunner(pipeline, concurrency=args.concurrency)
        result = await runner.run(faults, healthy_s=window_s, fault_s=window_s)
    finally:
        if hasattr(pipeline, "stop"):
            await pipeline.stop()

    summary = _summarise(result)
    environment = {"python": sys.version.split()[0], "platform": platform.platform()}
    markdown = _render_markdown(summary, environment)
    print(markdown)

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        if args.format in ("markdown", "both"):
            (out / "soak.md").write_text(markdown)
        if args.format in ("json", "both"):
            (out / "soak.json").write_text(
                json.dumps({"environment": environment, **summary}, indent=2)
            )

    if not summary["met"]:
        print(
            f"\nNFR-AVAIL-01 missed: {summary['availability']:.3%} < 99.9%",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Soak / fault-injection harness")
    parser.add_argument("--duration", type=float, default=60.0,
                        help="Total seconds, split evenly across all windows")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--fault", action="append",
                        help="Run only this fault (repeatable); default is all")
    parser.add_argument("--out", help="Directory to write the report into")
    parser.add_argument("--format", choices=("markdown", "json", "both"),
                        default="markdown")
    args = parser.parse_args()

    db = Path(__file__).resolve().parent / "_soak.db"
    _configure_environment(db)
    _quiet_logging()
    try:
        return asyncio.run(_run(args))
    finally:
        db.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
