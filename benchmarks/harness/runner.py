"""
Benchmark runner (PRD §14.1).

Executes a testbed once per ablation configuration and assembles the results
into a report. Testbeds implement the `Testbed` protocol; adding AgentDojo or
InjecAgent means adding a class here, not changing the harness.

Reproducibility (§14.4 requires a reproducible harness): every run records the
mediator settings that affect a verdict, so a published number can be
re-derived. Runs are isolated by `agent_id`, so no run can see another's
memory store.
"""

from __future__ import annotations

import platform
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from benchmarks.harness.ablation import AblationConfig
from benchmarks.harness.case import SuiteResult
from benchmarks.harness.metrics import SuiteMetrics, compute_metrics
from trust_mediator.config import settings


@runtime_checkable
class Testbed(Protocol):
    """A corpus plus the logic to run it against a configured mediator."""

    name: str
    #: Ablation axes this testbed genuinely varies. Anything outside this set
    #: is reported N/A rather than measured.
    supported_axes: tuple[str, ...]
    #: Which §14.2 ASR target applies to this testbed.
    asr_kpi: str

    async def run(self, config: AblationConfig, run_id: str) -> SuiteResult:
        ...


@dataclass
class BenchmarkReport:
    """Full result of a grid run: raw outcomes plus derived KPIs."""

    testbed: str
    asr_kpi: str
    started_at: str
    duration_s: float
    environment: dict[str, str]
    mediator_settings: dict[str, float | bool | str]
    results: list[SuiteResult] = field(default_factory=list)
    metrics: list[SuiteMetrics] = field(default_factory=list)

    @property
    def baseline(self) -> SuiteMetrics | None:
        """The undefended run, if the grid included one."""
        for m in self.metrics:
            if m.config_name == "undefended":
                return m
        return None

    def metrics_for(self, config_name: str) -> SuiteMetrics | None:
        for m in self.metrics:
            if m.config_name == config_name:
                return m
        return None

    @property
    def headline(self) -> SuiteMetrics | None:
        """The full-defence run — the configuration acceptance is judged on."""
        return self.metrics_for("full_defence")


class BenchmarkRunner:
    """Runs one testbed across an ablation grid."""

    def __init__(self, testbed: Testbed) -> None:
        self._testbed = testbed

    async def run_grid(self, configs: list[AblationConfig]) -> BenchmarkReport:
        started = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()

        results: list[SuiteResult] = []
        for config in configs:
            # A fresh agent_id per (config, run) keeps memory stores isolated,
            # so contradiction detection always starts from the same seeded
            # baseline and runs cannot contaminate each other.
            run_id = uuid.uuid4().hex[:12]
            result = await self._testbed.run(config, run_id)
            results.append(result)

        return BenchmarkReport(
            testbed=self._testbed.name,
            asr_kpi=self._testbed.asr_kpi,
            started_at=started_at,
            duration_s=round(time.perf_counter() - started, 3),
            environment={
                "python": sys.version.split()[0],
                "platform": platform.platform(),
            },
            mediator_settings=_captured_settings(),
            results=results,
            metrics=[compute_metrics(r) for r in results],
        )


def _captured_settings() -> dict[str, float | bool | str]:
    """
    The mediator settings that can change a verdict. Recorded with every
    report so a published KPI is reproducible (§14.4).
    """
    return {
        "scanner_backend": settings.scanner_backend,
        "scanner_block_threshold": settings.scanner_block_threshold,
        "scanner_escalate_threshold": settings.scanner_escalate_threshold,
        "scanner_transform_threshold": settings.scanner_transform_threshold,
        "scanner_shadow_mode": settings.scanner_shadow_mode,
        "memory_integrity_threshold": settings.memory_integrity_threshold,
        "memory_rescan_on_read": settings.memory_rescan_on_read,
    }
