"""
Benchmark CLI (PRD §14.4 — "reference implementation plus reproducible harness").

    python -m benchmarks.cli --testbed memory_poisoning
    python -m benchmarks.cli --testbed memory_poisoning --out results/ --format both

The harness runs against its own throwaway SQLite database so a benchmark run
never touches the application store. Environment is configured before any
`trust_mediator` import, because the DB engine is constructed at import time
from settings.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path


def _configure_environment(db_path: Path) -> None:
    """
    Pin the settings that affect a verdict, before trust_mediator is imported.

    The repo's `.env` sets production mode, docker-only hostnames and a live
    API key — all of which break a bare local run. These overrides mirror the
    documented test invocation in CLAUDE.md.
    """
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["TRUST_MEDIATOR_ENV"] = "test"
    os.environ["REDIS_URL"] = ""
    os.environ["TRUST_MEDIATOR_API_KEYS"] = ""
    # A shadow-mode scanner logs without enforcing, which would silently make
    # every scanner verdict a no-op and inflate ASR. Force enforcement.
    # (aliased settings fields bypass the TRUST_MEDIATOR_ prefix)
    os.environ["SCANNER_SHADOW_MODE"] = "false"


def _quiet_logging() -> None:
    """Per-decision INFO logs would drown the report; keep warnings and worse."""
    import structlog

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
    )


TESTBEDS = ("memory_poisoning", "injecagent")


def _build_testbed(name: str):
    if name == "memory_poisoning":
        from benchmarks.testbeds.memory_poisoning import MemoryPoisoningTestbed

        return MemoryPoisoningTestbed()
    if name == "injecagent":
        from benchmarks.testbeds.injecagent import InjecAgentTestbed

        return InjecAgentTestbed()
    raise SystemExit(f"Unknown testbed {name!r}. Available: {', '.join(TESTBEDS)}")


def _grid_for(name: str):
    """Each testbed varies the axes that actually gate its own attack path."""
    from benchmarks.harness.ablation import injection_ablation_grid, memory_ablation_grid

    return injection_ablation_grid() if name == "injecagent" else memory_ablation_grid()


async def _run(args: argparse.Namespace) -> int:
    from benchmarks.harness.report import render_json, render_markdown
    from benchmarks.harness.runner import BenchmarkRunner
    from trust_mediator.db.base import create_all_tables

    await create_all_tables()

    testbed = _build_testbed(args.testbed)
    runner = BenchmarkRunner(testbed)

    configs = _grid_for(args.testbed)
    if args.config:
        configs = [c for c in configs if c.name in args.config]
        if not configs:
            raise SystemExit(f"No configurations matched {args.config}")

    print(
        f"Running {testbed.name} across {len(configs)} configuration(s)…",
        file=sys.stderr,
    )
    report = await runner.run_grid(configs)

    markdown = render_markdown(report)
    if args.format in ("markdown", "both"):
        if args.out:
            path = Path(args.out) / f"{testbed.name}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            print(f"Wrote {path}", file=sys.stderr)
        else:
            print(markdown)

    if args.format in ("json", "both"):
        payload = render_json(report)
        if args.out:
            path = Path(args.out) / f"{testbed.name}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            print(f"Wrote {path}", file=sys.stderr)
        else:
            print(payload)

    # Exit non-zero when the headline configuration misses an applicable §14.2
    # target, so this can gate a release once the targets are expected to pass.
    headline = report.headline
    if headline is None:
        return 0
    checks = headline.kpi_checks(baseline=report.baseline, asr_kpi=report.asr_kpi)
    failed = [c for c in checks if c.applicable and not c.passed]
    if failed:
        print(
            "KPI targets missed: " + ", ".join(c.kpi for c in failed),
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="benchmarks.cli",
        description="TrustMediator evaluation harness (PRD §14)",
    )
    parser.add_argument(
        "--testbed", default="memory_poisoning", choices=TESTBEDS,
        help="Which testbed to run",
    )
    parser.add_argument(
        "--config", action="append",
        help="Run only this ablation configuration (repeatable)",
    )
    parser.add_argument(
        "--format", default="markdown", choices=("markdown", "json", "both"),
        help="Report format",
    )
    parser.add_argument(
        "--out", default=None,
        help="Directory to write report files into (default: stdout)",
    )
    parser.add_argument(
        "--db", default=None,
        help="SQLite path for the benchmark store (default: a temp file)",
    )
    parser.add_argument(
        "--keep-db", action="store_true",
        help="Do not delete the benchmark database on exit",
    )
    args = parser.parse_args(argv)

    if args.db:
        db_path = Path(args.db).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        db_path = Path.cwd() / ".benchmark_store.db"
    if db_path.exists():
        db_path.unlink()

    _configure_environment(db_path)
    _quiet_logging()

    try:
        return asyncio.run(_run(args))
    finally:
        if not args.keep_db and db_path.exists():
            db_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
