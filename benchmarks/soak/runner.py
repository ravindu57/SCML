"""
Soak driver (PRD §8.3, NFR-AVAIL-01).

Drives a representative mix of mediation operations continuously while
alternating healthy and faulted windows, and records the outcome of every
single call.

The mix matters: a soak that only scans context would never notice that the
policy store outage denies tool calls, because it never makes any. Each window
exercises all four decision paths so a fault lands somewhere observable.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from benchmarks.soak.faults import AppliedFault, Fault, InjectedFault


@dataclass
class CallOutcome:
    """One mediation call during the soak."""

    operation: str
    phase: str                     # "healthy" or the active fault's name
    elapsed_ms: float
    #: True when the caller received a decision of any kind — including a
    #: denial. False only when an exception escaped or the call timed out.
    decided: bool
    #: The decision rendered, for checking that faults fail in the right
    #: direction rather than merely returning *something*.
    verdict: str = ""
    error: str = ""


@dataclass
class PhaseWindow:
    """A stretch of the soak spent either healthy or under one fault."""

    phase: str
    fault: Fault | None
    started_at: float
    ended_at: float = 0.0
    outcomes: list[CallOutcome] = field(default_factory=list)


@dataclass
class SoakResult:
    windows: list[PhaseWindow] = field(default_factory=list)
    duration_s: float = 0.0
    #: Seconds between a fault clearing and the next successful decision.
    recovery_times_s: dict[str, float] = field(default_factory=dict)

    @property
    def outcomes(self) -> list[CallOutcome]:
        return [o for w in self.windows for o in w.outcomes]


class SoakRunner:
    """Runs sustained mixed load against one long-lived pipeline."""

    def __init__(self, pipeline, concurrency: int = 4, call_timeout_s: float = 5.0) -> None:
        self._pipeline = pipeline
        self._concurrency = concurrency
        self._timeout = call_timeout_s
        self._phase = "healthy"

    # ── The operation mix ─────────────────────────────────────────────────────

    async def _context(self) -> tuple[str, str]:
        from trust_mediator.models.context_envelope import ContextEnvelope, Provenance

        env = await self._pipeline.process_context(
            ContextEnvelope(
                session_id="soak",
                content="Quarterly revenue rose twelve percent across the region.",
                provenance=Provenance(source="rag_retrieval"),
            )
        )
        return "context", env.scanner_verdict.decision.value

    async def _tool_call(self) -> tuple[str, str]:
        from trust_mediator.models.tool_call import ToolCallRequest

        decision = await self._pipeline.process_tool_call(
            ToolCallRequest(
                session_id="soak", agent_id="web_search_agent", tool_name="web_search",
                arguments={"query": "weather"},
            )
        )
        return "tool_call", decision.decision.value

    async def _memory_write(self) -> tuple[str, str]:
        from trust_mediator.models.memory_record import MemoryWriteRequest

        result = await self._pipeline.process_memory_write(
            MemoryWriteRequest(
                session_id="soak",
                content="The user prefers quarterly reports in PDF form.",
                source="agent_observation",
            )
        )
        return "memory_write", result.verdict

    async def _output(self) -> tuple[str, str]:
        result = await self._pipeline.process_output(
            "Reach the team at ops@example.com.", session_id="soak"
        )
        return "output", "blocked" if result.blocked else "released"

    def _operations(self):
        return [self._context, self._tool_call, self._memory_write, self._output]

    # ── Driving ───────────────────────────────────────────────────────────────

    async def _one(self, op) -> CallOutcome:
        start = time.perf_counter()
        try:
            operation, verdict = await asyncio.wait_for(op(), timeout=self._timeout)
            return CallOutcome(
                operation=operation,
                phase=self._phase,
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
                decided=True,
                verdict=verdict,
            )
        except asyncio.TimeoutError:
            return CallOutcome(
                operation=op.__name__.lstrip("_"), phase=self._phase,
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
                decided=False, error="timeout",
            )
        except Exception as e:
            # An InjectedFault escaping to the caller is exactly the failure
            # this harness exists to catch: the mediator was supposed to turn
            # a broken dependency into a decision, and did not.
            return CallOutcome(
                operation=op.__name__.lstrip("_"), phase=self._phase,
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
                decided=False,
                error=f"{'injected-fault-escaped' if isinstance(e, InjectedFault) else type(e).__name__}: {e}",
            )

    async def _drive(self, window: PhaseWindow, seconds: float) -> None:
        stop_at = time.perf_counter() + seconds
        ops = self._operations()

        async def worker(offset: int) -> None:
            i = offset
            while time.perf_counter() < stop_at:
                window.outcomes.append(await self._one(ops[i % len(ops)]))
                i += 1
                await asyncio.sleep(0)  # yield so faults can be applied promptly

        await asyncio.gather(*(worker(i) for i in range(self._concurrency)))

    async def run(
        self,
        faults: list[Fault],
        healthy_s: float = 5.0,
        fault_s: float = 5.0,
    ) -> SoakResult:
        """
        Alternate a healthy window with a faulted window per fault.

        Healthy windows bracket every fault so recovery is measurable: a
        mediator that never recovers after a dependency returns is a different
        failure from one that degrades during the outage.
        """
        result = SoakResult()
        started = time.perf_counter()

        async def window(phase: str, fault: Fault | None, seconds: float) -> PhaseWindow:
            self._phase = phase
            w = PhaseWindow(phase=phase, fault=fault, started_at=time.perf_counter())
            applied: AppliedFault | None = fault.apply(self._pipeline) if fault else None
            try:
                await self._drive(w, seconds)
            finally:
                if applied:
                    applied.revert()
            w.ended_at = time.perf_counter()
            result.windows.append(w)
            return w

        await window("healthy", None, healthy_s)
        for fault in faults:
            await window(fault.name, fault, fault_s)
            recovery = await window("healthy", None, healthy_s)
            result.recovery_times_s[fault.name] = _first_success_offset(recovery)

        result.duration_s = time.perf_counter() - started
        return result


def _first_success_offset(window: PhaseWindow) -> float:
    """Seconds from the start of a recovery window to its first decision."""
    elapsed = 0.0
    for outcome in window.outcomes:
        elapsed += outcome.elapsed_ms / 1000.0
        if outcome.decided:
            return round(elapsed, 4)
    return float("inf")  # never recovered within the window
