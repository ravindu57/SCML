"""
Load benchmark CLI (PRD §8.1, §8.2).

    python -m benchmarks.load
    python -m benchmarks.load --target http --duration 10 --concurrency 32
    python -m benchmarks.load --format both --out benchmarks/results

Like the security harness, this pins its own environment before importing
`trust_mediator` (the DB engine is built at import time from settings) and uses
a throwaway store so a run never touches the application database.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import platform
import sys
from pathlib import Path

_LOAD_API_KEY = "load-benchmark-key"


def _configure_environment(db_path: Path) -> None:
    import os

    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["TRUST_MEDIATOR_ENV"] = "test"
    os.environ["REDIS_URL"] = ""
    os.environ["TRUST_MEDIATOR_API_KEYS"] = _LOAD_API_KEY
    os.environ["SCANNER_SHADOW_MODE"] = "false"
    # Without this the run measures slowapi rejecting traffic, not mediation:
    # the default 200/minute would 429 within the first second.
    os.environ["TRUST_MEDIATOR_RATE_LIMIT"] = "10000000/minute"


def _quiet_logging() -> None:
    import structlog

    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
    logging.getLogger("sqlalchemy").setLevel(logging.ERROR)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR)
    )


async def _measure_audit_drain_rate(pipeline, sample_s: float = 2.0) -> float:
    """
    Observed audit write throughput (NFR-PERF-04).

    A raw backlog figure is meaningless on its own — drive the mediator hard
    enough and any async writer falls behind. What matters is whether the
    writer keeps up at the *target* load, so measure the drain rate directly
    and let the report compare it against NFR-SCAL-01's 100 req/s.
    """
    import time as _time

    queue = pipeline._audit._queue
    before = queue.qsize()
    if before == 0:
        return 0.0
    started = _time.perf_counter()
    await asyncio.sleep(sample_s)
    elapsed = _time.perf_counter() - started
    drained = before - queue.qsize()
    return drained / elapsed if elapsed > 0 and drained > 0 else 0.0


async def _shutdown_audit(pipeline) -> None:
    """
    Stop the audit writer without waiting for a full drain.

    `AuditLogger.stop()` awaits `queue.join()`, which never returns when the
    writer is behind — and the backlog figures in the report are sampled at end
    of run, so a full drain buys nothing. Cancel directly and swallow the
    CancelledError raised out of the in-flight aiosqlite query (CancelledError
    derives from BaseException, so a bare `except Exception` misses it).
    """
    import contextlib

    audit = pipeline._audit
    task = getattr(audit, "_worker_task", None)
    if task is not None:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
    with contextlib.suppress(Exception):
        await audit._kafka.stop()


async def _run(args: argparse.Namespace, db_path: Path) -> int:
    from benchmarks.load.metrics import compute_load_metrics
    from benchmarks.load.report import render_json, render_markdown
    from benchmarks.load.runner import LoadRunner
    from benchmarks.load.scenarios import SCENARIOS, get_scenario
    from trust_mediator.api.dependencies import get_pipeline
    from trust_mediator.db.base import create_all_tables

    await create_all_tables()

    scenarios = (
        [get_scenario(n) for n in args.scenario] if args.scenario else SCENARIOS
    )

    pipeline = get_pipeline()
    await pipeline.start()  # audit writer must run, or the queue never drains

    targets = ("pipeline", "http") if args.target == "both" else (args.target,)

    client = None
    if "http" in targets:
        from httpx import ASGITransport, AsyncClient

        from trust_mediator.api.app import create_app

        app = create_app()
        # Importing the app calls configure_logging(), which re-installs
        # structlog's default processors and undoes the quiet setup from
        # main(). Re-apply it or the report drowns in per-request logs.
        _quiet_logging()
        client = AsyncClient(
            transport=ASGITransport(app=app), base_url="http://loadtest", timeout=30.0
        )

    runner = LoadRunner(pipeline=pipeline, http_client=client, api_key=_LOAD_API_KEY)

    results = []
    try:
        for target in targets:
            for scenario in scenarios:
                print(f"  {scenario.name} ({target}) …", file=sys.stderr, flush=True)
                result = await runner.run(
                    scenario,
                    target=target,
                    concurrency=args.concurrency,
                    duration_s=args.duration,
                    warmup_s=args.warmup,
                )
                if result.error_samples:
                    print(
                        f"    {result.errors} errors, e.g. {result.error_samples[0]}",
                        file=sys.stderr,
                    )
                results.append(result)
    finally:
        if client is not None:
            await client.aclose()

    audit_drain_rps = await _measure_audit_drain_rate(pipeline)

    metrics = [compute_load_metrics(r) for r in results]
    environment = {
        "audit_drain_rps": f"{audit_drain_rps:.0f}",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "database": "sqlite (throwaway)",
        "duration_s": str(args.duration),
        "concurrency": str(args.concurrency),
        "warmup_s": str(args.warmup),
        "target": args.target,
    }

    if args.format in ("markdown", "both"):
        markdown = render_markdown(metrics, environment)
        if args.out:
            path = Path(args.out) / "load.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            print(f"Wrote {path}", file=sys.stderr)
        else:
            print(markdown)

    if args.format in ("json", "both"):
        payload = render_json(metrics, environment)
        if args.out:
            path = Path(args.out) / "load.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            print(f"Wrote {path}", file=sys.stderr)
        else:
            print(payload)

    await _shutdown_audit(pipeline)

    failed = [
        (m.scenario, c.kpi)
        for m in metrics
        for c in m.kpi_checks()
        if c.applicable and not c.passed
    ]
    if failed:
        print(
            "NFR targets missed: "
            + ", ".join(f"{s}/{k}" for s, k in failed),
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="benchmarks.load",
        description="TrustMediator load and latency benchmark (PRD §8.1, §8.2)",
    )
    parser.add_argument(
        "--target", default="both", choices=("pipeline", "http", "both"),
        help=(
            "pipeline = mediator cost only (NFR-PERF-01/03); http = full ASGI "
            "stack (NFR-SCAL-01); both = one report covering each"
        ),
    )
    parser.add_argument(
        "--scenario", action="append",
        help="Run only this scenario (repeatable)",
    )
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--duration", type=float, default=5.0, help="seconds per scenario")
    parser.add_argument("--warmup", type=float, default=1.0, help="seconds, discarded")
    parser.add_argument("--format", default="markdown", choices=("markdown", "json", "both"))
    parser.add_argument("--out", default=None, help="Directory for report files")
    parser.add_argument("--db", default=None)
    args = parser.parse_args(argv)

    db_path = (
        Path(args.db).resolve() if args.db else Path.cwd() / ".load_store.db"
    )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    _configure_environment(db_path)
    _quiet_logging()

    try:
        return asyncio.run(_run(args, db_path))
    finally:
        if db_path.exists():
            db_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
