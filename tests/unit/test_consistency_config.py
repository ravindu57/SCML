"""
Consistency checker tunables (PRD §6.5, FR-MI-02; CLAUDE.md config rule).

The §14.3 ablation makes this the load-bearing layer of the memory-poisoning
defence — disabling it takes ASR from 33.3% to 64.6%, a larger swing than the
injection scanner contributes. Yet its four thresholds were literals in the
module, so the component doing most of the work was the one an operator could
not adjust without editing code.

These tests assert two separate things:

  * the defaults reproduce the previous constants exactly, so exposing them
    cannot have moved a committed benchmark result; and
  * each threshold actually reaches the behaviour it names, so a future edit
    that hardcodes one again fails here rather than silently pinning it.

The second matters more than it looks. A setting that is read but ignored is
worse than a constant: it advertises control that does not exist.
"""

from __future__ import annotations

import pytest

from trust_mediator.config import Settings
from trust_mediator.modules.memory_integrity.consistency_checker import (
    ConsistencyChecker,
    ConsistencyReport,
)


class _Rec:
    """Minimal stand-in for MemoryRecord — the checker reads id and content."""

    def __init__(self, rid: str, content: str) -> None:
        self.id = rid
        self.content = content


class TestDefaultsMatchThePreviousConstants:
    """Exposing a constant must not change it."""

    @pytest.mark.parametrize(
        "field,expected",
        [
            ("memory_consistency_suspicion_threshold", 0.40),
            ("memory_contradiction_overlap_min", 0.25),
            ("memory_negation_divergence_min", 0.30),
            ("memory_contradiction_report_min", 0.30),
        ],
    )
    def test_default(self, field, expected):
        assert getattr(Settings(), field) == pytest.approx(expected)


class TestSuspicionThresholdIsHonoured:
    def test_risk_below_the_threshold_is_not_suspicious(self, monkeypatch):
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_consistency_suspicion_threshold", 0.9
        )
        report = ConsistencyReport(instruction_score=0.5)
        assert report.is_suspicious is False

    def test_lowering_it_makes_the_same_risk_suspicious(self, monkeypatch):
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_consistency_suspicion_threshold", 0.1
        )
        report = ConsistencyReport(instruction_score=0.5)
        assert report.is_suspicious is True

    def test_flags_still_win_regardless(self, monkeypatch):
        """
        A flag is a positive finding, not a score. Raising the threshold must
        not suppress one, or an operator tuning for noise would silently switch
        off contradiction reporting.
        """
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_consistency_suspicion_threshold", 1.0
        )
        report = ConsistencyReport(instruction_score=0.0, flags=["contradiction:x"])
        assert report.is_suspicious is True


class TestContradictionThresholdsAreHonoured:
    """
    Uses a genuine contradiction pair — same subject, negated claim — so the
    detector is exercised rather than mocked.
    """

    # Measured: Jaccard overlap 0.625, negation divergence 0.600. Both sit
    # strictly between the defaults and 0.99, so raising either floor to 0.99
    # genuinely crosses it. A tighter pair would tokenise identically — the
    # stopword list strips "not", so a sentence and its negation can reach
    # overlap 1.0 — and the floor tests would pass for the wrong reason.
    CANDIDATE = (
        "The billing service deployment target is not prod-eu-1 "
        "according to the migration notes."
    )
    EXISTING = [_Rec("rec-00000001", "The billing service deployment target is prod-eu-1.")]

    def test_detected_at_default_settings(self):
        report = ConsistencyChecker().check(self.CANDIDATE, self.EXISTING)
        assert report.contradiction_score > 0.0, (
            "the fixture is meant to be a real contradiction; if this fails the "
            "test below proves nothing"
        )

    def test_raising_the_overlap_floor_suppresses_it(self, monkeypatch):
        """Above the pair's actual overlap, they are no longer compared at all."""
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_contradiction_overlap_min", 0.99
        )
        report = ConsistencyChecker().check(self.CANDIDATE, self.EXISTING)
        assert report.contradiction_score == 0.0

    def test_raising_the_negation_floor_suppresses_it(self, monkeypatch):
        """Overlap still qualifies them; the negation is judged too weak."""
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_negation_divergence_min", 0.99
        )
        report = ConsistencyChecker().check(self.CANDIDATE, self.EXISTING)
        assert report.contradiction_score == 0.0

    def test_report_min_hides_the_citation_without_changing_the_verdict(
        self, monkeypatch
    ):
        """
        The distinction this threshold exists for: it controls which records are
        *named*, not whether a contradiction was found. Raising it should strip
        the evidence while leaving the score — the opposite would mean an
        operator could silently disable detection while thinking they were
        reducing report noise.
        """
        monkeypatch.setattr(
            "trust_mediator.config.settings.memory_contradiction_report_min", 0.99
        )
        report = ConsistencyChecker().check(self.CANDIDATE, self.EXISTING)
        assert report.contradiction_score > 0.0
        assert report.contradicted_ids == []


def test_no_thresholds_remain_hardcoded_in_the_module():
    """
    Guards the rule rather than one instance of it: a bare float compared
    against a score is how all four started. Catches a reintroduction that the
    behavioural tests above would miss if it were added to a new code path.
    """
    import re
    from pathlib import Path

    import trust_mediator.modules.memory_integrity.consistency_checker as mod

    source = Path(mod.__file__).read_text()
    # Strip the pattern table, whose weights are detector definitions rather
    # than operator-facing tunables.
    source = re.sub(r"_INSTRUCTION_PATTERNS.*?\n\]", "", source, flags=re.S)

    offenders = re.findall(r"[<>]=?\s*0\.\d+", source)
    assert not offenders, f"hardcoded threshold(s) reintroduced: {offenders}"
