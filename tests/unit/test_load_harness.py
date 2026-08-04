"""
Unit tests for the load harness (PRD §8.1, §8.2).

The KPI-scoping logic carries most of the risk here. NFR-PERF-03 budgets the
*policy engine's* decision latency and §8.1 budgets the *fast path*; applying
either to a measurement that includes HTTP transport or a database round trip
would produce a failure the PRD never asked for — or, worse, a pass that
overstates capacity.
"""

from __future__ import annotations

from benchmarks.load.metrics import NFR_TARGETS, compute_load_metrics
from benchmarks.load.runner import LoadResult
from benchmarks.load.scenarios import SCENARIOS, get_scenario


def _result(**kw) -> LoadResult:
    defaults = dict(
        scenario="s",
        kind="fast_path",
        target="pipeline",
        concurrency=4,
        elapsed_s=2.0,
        completed=200,
        errors=0,
        latencies_ms=[1.0] * 200,
        audit_backlog=0,
    )
    defaults.update(kw)
    return LoadResult(**defaults)


class TestTargets:
    def test_targets_match_the_prd(self):
        """§8.1/§8.2 budgets are contractual — a silent edit moves the goalposts."""
        assert NFR_TARGETS["latency_p50_ms"] == 120.0
        assert NFR_TARGETS["latency_p95_ms"] == 400.0
        assert NFR_TARGETS["policy_p95_ms"] == 10.0
        assert NFR_TARGETS["throughput_rps"] == 100.0


class TestMetrics:
    def test_throughput_is_completed_over_elapsed(self):
        m = compute_load_metrics(_result(completed=500, elapsed_s=2.0))
        assert m.throughput_rps == 250.0

    def test_error_rate_counts_against_attempts(self):
        m = compute_load_metrics(_result(completed=90, errors=10))
        assert m.error_rate == 0.1

    def test_empty_run_does_not_divide_by_zero(self):
        m = compute_load_metrics(
            _result(completed=0, errors=0, elapsed_s=0.0, latencies_ms=[])
        )
        assert m.throughput_rps == 0.0
        assert m.error_rate == 0.0
        assert m.latency_p95_ms == 0.0

    def test_percentiles_ordered(self):
        latencies = [float(i) for i in range(1, 101)]
        m = compute_load_metrics(_result(latencies_ms=latencies))
        assert m.latency_p50_ms <= m.latency_p95_ms <= m.latency_p99_ms
        assert m.latency_max_ms == 100.0


class TestKpiScoping:
    """The load harness must not credit or blame a budget the PRD never set."""

    def _check(self, metrics, kpi):
        return next(c for c in metrics.kpi_checks() if c.kpi == kpi)

    def test_fast_path_latency_is_judged(self):
        m = compute_load_metrics(_result(kind="fast_path"))
        assert self._check(m, "latency_p95_ms").applicable

    def test_db_bound_latency_is_not_judged(self):
        """
        §8.1 scopes its budget to the fast path. memory_write reads and writes
        the memory store, so holding it to 400ms would fail the system for a
        cost the requirement never covered.
        """
        m = compute_load_metrics(_result(kind="db_bound", latencies_ms=[900.0] * 10))
        check = self._check(m, "latency_p95_ms")
        assert not check.applicable
        assert check.status == "N/A"

    def test_policy_budget_applies_to_the_engine(self):
        m = compute_load_metrics(_result(kind="deterministic", target="pipeline"))
        check = self._check(m, "policy_p95_ms")
        assert check.applicable
        assert check.passed

    def test_policy_budget_not_applied_over_http(self):
        """
        NFR-PERF-03 says "policy engine decision latency (deterministic path)".
        Over HTTP the figure also contains routing, auth and serialisation.
        """
        m = compute_load_metrics(
            _result(kind="deterministic", target="http", latencies_ms=[50.0] * 10)
        )
        check = self._check(m, "policy_p95_ms")
        assert not check.applicable
        assert "pipeline" in check.note

    def test_errors_are_always_judged(self):
        """An error is a failure on any path, fast or not."""
        m = compute_load_metrics(_result(kind="db_bound", completed=90, errors=10))
        check = self._check(m, "error_rate")
        assert check.applicable
        assert not check.passed


class TestScenarios:
    def test_every_scenario_has_a_pipeline_driver(self):
        """A scenario the runner cannot drive would silently report zero work."""
        supported = ("/context", "/tool-call", "/output", "/memory/write")
        for scenario in SCENARIOS:
            assert scenario.path.endswith(supported), scenario.name

    def test_fast_path_classification_matches_prd_scope(self):
        assert get_scenario("context_benign").counts_toward_fast_path
        assert get_scenario("tool_call_policy").counts_toward_fast_path
        # Touches the memory store — outside §8.1.
        assert not get_scenario("memory_write").counts_toward_fast_path

    def test_scenario_names_unique(self):
        names = [s.name for s in SCENARIOS]
        assert len(names) == len(set(names))

    def test_unknown_scenario_is_rejected(self):
        import pytest

        with pytest.raises(SystemExit):
            get_scenario("does_not_exist")


class TestAuditQueueIsolation:
    def test_drain_empties_the_queue(self):
        """
        Scenarios must start from an empty audit queue — a backlog left by a
        previous run competes for the event loop and depresses throughput by
        a third or more, which would read as a regression.
        """
        import asyncio

        from benchmarks.load.runner import LoadRunner

        class _FakePipeline:
            class _Audit:
                def __init__(self):
                    self._queue = asyncio.Queue()

            def __init__(self):
                self._audit = self._Audit()

        pipeline = _FakePipeline()
        for i in range(50):
            pipeline._audit._queue.put_nowait(i)

        runner = LoadRunner(pipeline=pipeline)
        assert runner._drain_audit_queue() == 50
        assert pipeline._audit._queue.qsize() == 0
        assert runner._audit_backlog() == 0
