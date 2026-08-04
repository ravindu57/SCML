"""
Load driver (PRD §8.1, §8.2).

Runs a scenario with N cooperating async workers for a fixed duration, after a
warm-up phase, and records per-request latency.

Warm-up is not cosmetic: the first call trains or unpickles the TF-IDF
classifier, populates the 30-second policy cache and opens the first database
connection. Including those in the sample would report a cold-start artifact
as steady-state latency.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from benchmarks.load.scenarios import Scenario


@dataclass
class LoadResult:
    scenario: str
    kind: str
    target: str
    concurrency: int
    elapsed_s: float
    completed: int
    errors: int
    latencies_ms: list[float] = field(default_factory=list)
    audit_backlog: int = 0
    error_samples: list[str] = field(default_factory=list)


class LoadRunner:
    """
    Drives one scenario against one target.

    Targets:
      "pipeline" — direct MediationPipeline calls (the mediator's own cost)
      "http"     — through the ASGI app (adds routing, auth, serialisation)
    """

    def __init__(
        self,
        pipeline=None,
        http_client=None,
        api_key: str = "",
    ) -> None:
        self._pipeline = pipeline
        self._client = http_client
        self._api_key = api_key

    # ── Per-request drivers ───────────────────────────────────────────────────

    async def _call_pipeline(self, scenario: Scenario) -> None:
        from trust_mediator.models.context_envelope import ContextEnvelope, Provenance
        from trust_mediator.models.memory_record import MemoryWriteRequest
        from trust_mediator.models.tool_call import ToolCallRequest

        p = scenario.payload
        if scenario.path.endswith("/context"):
            await self._pipeline.process_context(
                ContextEnvelope(
                    session_id=p["session_id"],
                    content=p["content"],
                    provenance=Provenance(source=p["source"]),
                )
            )
        elif scenario.path.endswith("/tool-call"):
            await self._pipeline.process_tool_call(
                ToolCallRequest(
                    session_id=p["session_id"],
                    agent_id=p["agent_id"],
                    tool_name=p["tool_name"],
                    arguments=p["arguments"],
                )
            )
        elif scenario.path.endswith("/output"):
            await self._pipeline.process_output(
                p["content"],
                session_id=p["session_id"],
                destination=p["destination"],
            )
        elif scenario.path.endswith("/memory/write"):
            await self._pipeline.process_memory_write(
                MemoryWriteRequest(
                    session_id=p["session_id"],
                    content=p["content"],
                    source=p["source"],
                )
            )
        else:
            raise ValueError(f"No pipeline driver for {scenario.path}")

    async def _call_http(self, scenario: Scenario) -> None:
        headers = {"X-API-Key": self._api_key} if self._api_key else {}
        resp = await self._client.post(
            scenario.path, json=scenario.payload, headers=headers
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")

    async def _one(self, scenario: Scenario, target: str) -> None:
        if target == "pipeline":
            await self._call_pipeline(scenario)
        else:
            await self._call_http(scenario)

    # ── Driver ────────────────────────────────────────────────────────────────

    async def run(
        self,
        scenario: Scenario,
        target: str = "pipeline",
        concurrency: int = 8,
        duration_s: float = 5.0,
        warmup_s: float = 1.0,
    ) -> LoadResult:
        # Warm-up — excluded from the sample.
        warm_deadline = time.perf_counter() + warmup_s
        while time.perf_counter() < warm_deadline:
            try:
                await self._one(scenario, target)
            except Exception:
                break

        # Discard audit events queued by warm-up and by previous scenarios.
        #
        # Without this the runs contaminate each other: the pipeline target
        # enqueues tens of thousands of events in seconds, and the background
        # writer draining that backlog then competes for the event loop with
        # whatever scenario runs next — depressing its throughput by a third or
        # more. Each scenario must start from an empty queue to be comparable.
        # Dropping events is sound here because this measures the request path,
        # not audit durability; the per-scenario backlog figure is still taken
        # from events this scenario itself produced.
        self._drain_audit_queue()

        latencies: list[float] = []
        errors = 0
        error_samples: list[str] = []
        stop_at = time.perf_counter() + duration_s

        async def worker() -> None:
            nonlocal errors
            while time.perf_counter() < stop_at:
                start = time.perf_counter()
                try:
                    await self._one(scenario, target)
                except Exception as e:  # noqa: BLE001 — recorded, not swallowed
                    errors += 1
                    if len(error_samples) < 5:
                        error_samples.append(f"{type(e).__name__}: {e}")
                    continue
                latencies.append((time.perf_counter() - start) * 1000.0)

        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        elapsed = time.perf_counter() - started

        return LoadResult(
            scenario=scenario.name,
            kind=scenario.kind,
            target=target,
            concurrency=concurrency,
            elapsed_s=elapsed,
            completed=len(latencies),
            errors=errors,
            latencies_ms=latencies,
            audit_backlog=self._audit_backlog(),
            error_samples=error_samples,
        )

    def _drain_audit_queue(self) -> int:
        """Discard queued audit events so each scenario starts from empty."""
        if self._pipeline is None:
            return 0
        try:
            queue = self._pipeline._audit._queue
        except AttributeError:
            return 0
        dropped = 0
        while not queue.empty():
            try:
                queue.get_nowait()
                queue.task_done()
                dropped += 1
            except Exception:  # noqa: BLE001 — queue raced empty
                break
        return dropped

    def _audit_backlog(self) -> int:
        """
        Depth of the audit queue at end of run (NFR-PERF-04).

        Enqueueing is O(1) and off the request path, but if the background
        writer cannot drain as fast as requests arrive, the cost has been
        deferred into unbounded memory rather than eliminated. Reporting the
        backlog makes that visible instead of leaving it as an assumption.
        """
        if self._pipeline is None:
            return 0
        try:
            return self._pipeline._audit._queue.qsize()
        except Exception:
            return 0
