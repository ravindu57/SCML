"""
Latency and throughput KPIs (PRD §8.1, §8.2).

Targets transcribed verbatim from the PRD NFR tables. `KpiCheck` is reused
from the security harness so PASS/FAIL means the same thing in both reports.
"""

from __future__ import annotations

from dataclasses import dataclass

from benchmarks.harness.metrics import KpiCheck, percentile

#: §8.1 / §8.2 targets.
NFR_TARGETS: dict[str, float] = {
    "latency_p50_ms": 120.0,   # NFR-PERF-01
    "latency_p95_ms": 400.0,   # NFR-PERF-01
    "policy_p95_ms": 10.0,     # NFR-PERF-03
    "throughput_rps": 100.0,   # NFR-SCAL-01
    "error_rate": 0.0,         # errors are never acceptable under nominal load
}


@dataclass
class LoadMetrics:
    scenario: str
    kind: str
    target: str
    concurrency: int
    elapsed_s: float
    completed: int
    errors: int
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_mean_ms: float
    latency_max_ms: float
    throughput_rps: float
    #: Audit events still queued when the run ended. NFR-PERF-04 takes audit
    #: writes off the request path; a queue that grows without bound means the
    #: cost was deferred rather than removed.
    audit_backlog: int = 0

    @property
    def error_rate(self) -> float:
        total = self.completed + self.errors
        return self.errors / total if total else 0.0

    def kpi_checks(self) -> list[KpiCheck]:
        """
        KPIs applicable to this scenario. §8.1's latency target is scoped to
        the fast path, so a database-bound scenario reports N/A rather than
        being judged against a budget the PRD never set for it.
        """
        fast_path = self.kind in ("fast_path", "deterministic")
        checks = [
            KpiCheck(
                "latency_p50_ms",
                self.latency_p50_ms,
                NFR_TARGETS["latency_p50_ms"],
                lower_is_better=True,
                applicable=fast_path,
                note="" if fast_path else "not on the §8.1 fast path",
            ),
            KpiCheck(
                "latency_p95_ms",
                self.latency_p95_ms,
                NFR_TARGETS["latency_p95_ms"],
                lower_is_better=True,
                applicable=fast_path,
                note="" if fast_path else "not on the §8.1 fast path",
            ),
            KpiCheck(
                "error_rate",
                self.error_rate,
                NFR_TARGETS["error_rate"],
                lower_is_better=True,
            ),
        ]
        if self.kind == "deterministic":
            # NFR-PERF-03 scopes its 10ms budget to "policy engine decision
            # latency (deterministic path)" — the engine, not the endpoint.
            # Over HTTP the number also contains routing, auth, rate limiting
            # and JSON serialisation, so judging it there would fail the
            # requirement for costs it never covered.
            via_engine = self.target == "pipeline"
            checks.append(
                KpiCheck(
                    "policy_p95_ms",
                    self.latency_p95_ms,
                    NFR_TARGETS["policy_p95_ms"],
                    lower_is_better=True,
                    applicable=via_engine,
                    note=(
                        "NFR-PERF-03 deterministic path"
                        if via_engine
                        else "measured over HTTP; NFR-PERF-03 scopes this to the "
                        "engine — use --target pipeline"
                    ),
                )
            )
        return checks


def compute_load_metrics(result) -> LoadMetrics:
    """Aggregate a LoadResult into §8.1/§8.2 KPIs."""
    latencies = result.latencies_ms
    return LoadMetrics(
        scenario=result.scenario,
        kind=result.kind,
        target=result.target,
        concurrency=result.concurrency,
        elapsed_s=result.elapsed_s,
        completed=result.completed,
        errors=result.errors,
        latency_p50_ms=percentile(latencies, 50),
        latency_p95_ms=percentile(latencies, 95),
        latency_p99_ms=percentile(latencies, 99),
        latency_mean_ms=sum(latencies) / len(latencies) if latencies else 0.0,
        latency_max_ms=max(latencies) if latencies else 0.0,
        throughput_rps=(result.completed / result.elapsed_s) if result.elapsed_s else 0.0,
        audit_backlog=result.audit_backlog,
    )
