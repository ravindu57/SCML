"""
Soak and fault-injection harness (PRD §8.3, NFR-AVAIL-01).

The harness produces the availability number, so a defect in it is worse than
no measurement: it would publish a passing figure that means nothing. Two
properties carry that weight and are tested directly.

**A denial is availability.** §9 requires a mediator that cannot verify a tool
call to deny it, so a deny during a database outage is the system working as
specified. Counting it as downtime would penalise correct behaviour and reward
a mediator that failed open — the harness would then report its worst possible
failure as its best score.

**Faults must revert exactly.** Windows alternate against one long-lived
pipeline, so a fault that leaks past its window silently contaminates every
later measurement, including the healthy baseline it is compared against.
"""

from __future__ import annotations

import pytest

from benchmarks.soak.__main__ import _summarise
from benchmarks.soak.faults import ALL_FAULTS, InjectedFault, get_fault
from benchmarks.soak.runner import CallOutcome, PhaseWindow, SoakResult


# ── Fault application ─────────────────────────────────────────────────────────


class _Leaf:
    def __init__(self) -> None:
        self.predict = lambda text: 0.0
        self.scan = lambda text: []
        self.get_policy = None
        self.list_active = None
        self.save = None
        self.redact = lambda *a, **k: None
        self.append_chained = None
        self.append_chained_batch = None


class _FakePipeline:
    """Mirrors only the attribute paths the fault definitions reach into."""

    def __init__(self) -> None:
        self._scanner = type("S", (), {"_classifier": _Leaf(), "_filter": _Leaf()})()
        self._policy_engine = type("P", (), {"_loader": _Leaf()})()
        self._memory = type("M", (), {"_repo": _Leaf()})()
        self._redactor = _Leaf()
        self._audit = type("A", (), {"_repo": _Leaf()})()


@pytest.mark.parametrize("fault", ALL_FAULTS, ids=lambda f: f.name)
def test_every_fault_applies_and_reverts_exactly(fault):
    """
    The originals must come back identical, not merely callable. A fault that
    leaves a wrapper behind would degrade every subsequent window, and the
    healthy baseline would drift toward the faulted one — hiding the very
    degradation the soak exists to measure.
    """
    pipeline = _FakePipeline()

    def snapshot():
        return {
            (id(obj), attr): getattr(obj, attr)
            for obj in (
                pipeline._scanner._classifier,
                pipeline._scanner._filter,
                pipeline._policy_engine._loader,
                pipeline._memory._repo,
                pipeline._redactor,
                pipeline._audit._repo,
            )
            for attr in vars(obj)
        }

    before = snapshot()
    applied = fault.apply(pipeline)
    assert snapshot() != before, f"{fault.name} patched nothing"
    applied.revert()
    assert snapshot() == before, f"{fault.name} did not restore the originals"


def test_unknown_fault_is_rejected_with_the_available_names():
    with pytest.raises(SystemExit) as exc:
        get_fault("no_such_fault")
    assert "scanner_down" in str(exc.value)


def test_every_fault_declares_what_section_9_requires():
    """
    `expected` is what makes a report readable: it says which §9 row the window
    exercises, so a reviewer can tell "denied everything" from "broke".
    """
    for fault in ALL_FAULTS:
        assert fault.expected.strip(), f"{fault.name} has no expected behaviour"


def test_injected_faults_are_distinguishable_from_real_defects():
    assert issubclass(InjectedFault, RuntimeError)


# ── Availability accounting ───────────────────────────────────────────────────


def _window(phase: str, outcomes: list[CallOutcome]) -> PhaseWindow:
    w = PhaseWindow(phase=phase, fault=None, started_at=0.0)
    w.outcomes = outcomes
    return w


def _decided(verdict: str, phase: str = "healthy") -> CallOutcome:
    return CallOutcome(
        operation="tool_call", phase=phase, elapsed_ms=1.0, decided=True, verdict=verdict
    )


def _escaped(phase: str) -> CallOutcome:
    return CallOutcome(
        operation="tool_call", phase=phase, elapsed_ms=1.0, decided=False,
        error="injected-fault-escaped: db down",
    )


class TestADenialCountsAsAvailable:
    """The load-bearing definition. If this inverts, the number is worthless."""

    def test_denials_are_fully_available(self):
        result = SoakResult(windows=[_window("policy_store_down", [
            _decided("mediator_error", "policy_store_down") for _ in range(10)
        ])])
        assert _summarise(result)["availability"] == 1.0

    def test_quarantines_and_blocks_are_available_too(self):
        result = SoakResult(windows=[_window("mixed", [
            _decided("quarantine"), _decided("blocked"), _decided("allow"),
        ])])
        assert _summarise(result)["availability"] == 1.0

    def test_an_escaped_exception_is_not_available(self):
        result = SoakResult(windows=[_window("memory_store_down", [
            _decided("allow"), _escaped("memory_store_down"),
        ])])
        summary = _summarise(result)
        assert summary["availability"] == 0.5
        assert summary["met"] is False


class TestPerPhaseBreakdown:
    def test_a_bad_window_cannot_hide_in_a_healthy_average(self):
        """
        99 healthy calls and 1 escaped fault is 99% overall, which reads as
        nearly fine. The per-phase row must show the faulted window at 0%.
        """
        result = SoakResult(windows=[
            _window("healthy", [_decided("allow") for _ in range(99)]),
            _window("memory_store_down", [_escaped("memory_store_down")]),
        ])
        summary = _summarise(result)
        assert summary["by_phase"]["healthy"]["availability"] == 1.0
        assert summary["by_phase"]["memory_store_down"]["availability"] == 0.0

    def test_escaped_errors_are_reported_by_kind(self):
        result = SoakResult(windows=[
            _window("memory_store_down", [_escaped("memory_store_down")])
        ])
        errors = _summarise(result)["by_phase"]["memory_store_down"]["errors"]
        assert errors == {"injected-fault-escaped": 1}


class TestTargetGate:
    @pytest.mark.parametrize(
        "decided,total,met",
        [
            (1000, 1000, True),
            # Exactly 99.9%. NFR-AVAIL-01 reads "≥ 99.9%", so the boundary is
            # inclusive and this must pass — asserting otherwise would push the
            # harness to fail a run that meets the requirement.
            (999, 1000, True),
            (998, 1000, False),
            (9990, 10000, True),
            (9989, 10000, False),
        ],
    )
    def test_the_999_boundary(self, decided, total, met):
        outcomes = [_decided("allow") for _ in range(decided)]
        outcomes += [_escaped("healthy") for _ in range(total - decided)]
        assert _summarise(SoakResult(windows=[_window("healthy", outcomes)]))["met"] is met

    def test_an_empty_run_does_not_claim_success(self):
        """Zero calls is no evidence; it must not divide by zero or pass."""
        summary = _summarise(SoakResult(windows=[]))
        assert summary["availability"] == 0.0
        assert summary["met"] is False
