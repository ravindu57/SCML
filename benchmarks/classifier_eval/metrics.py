"""
Classifier evaluation metrics for the §6.3a protocol (FR-SC-06/07/08).

These compute exactly the table FR-SC-07 specifies:
  - held-out ROC-AUC                    ≥ 0.85
  - attack recall at operating threshold ≥ 0.50
  - false-positive rate at that threshold ≤ 3%

Dependency-free by design, so the harness runs in the same bare environment as
the test suite. ROC-AUC is computed by the standard Mann-Whitney / rank
formulation, not by fitting a curve.
"""

from __future__ import annotations

from dataclasses import dataclass

#: FR-SC-07 thresholds, verbatim from the addendum table.
FR_SC07_TARGETS = {
    "roc_auc": 0.85,
    "attack_recall": 0.50,
    "false_positive_rate": 0.03,
}


@dataclass(frozen=True)
class ScoredSample:
    """One (classifier score, true label) pair. label: True = attack (positive)."""

    text: str
    score: float
    is_attack: bool


def roc_auc(samples: list[ScoredSample]) -> float:
    """Area under the ROC curve by pairwise Mann-Whitney U rank method."""
    positives = sorted(s.score for s in samples if s.is_attack)
    negatives = sorted(s.score for s in samples if not s.is_attack)
    if not positives or not negatives:
        return 0.5
    # Number of (neg, pos) pairs where score(neg) < score(pos); ties count half.
    better = 0.0
    # Two-pointer over the sorted negative and positive scores.
    j = 0
    n_neg = len(negatives)
    for pos in positives:
        # negatives[0:j] all < pos
        while j < n_neg and negatives[j] < pos:
            j += 1
        # Count ties among the remaining negatives equal to pos.
        tie_start = j
        tie_end = j
        while tie_end < n_neg and negatives[tie_end] == pos:
            tie_end += 1
        better += j + (tie_end - tie_start) / 2.0
    total = n_neg * len(positives)
    return better / total if total else 0.5


@dataclass(frozen=True)
class ThresholdMetrics:
    """Recall/FPR at a single operating threshold (score >= threshold = flagged)."""

    threshold: float
    attack_recall: float
    false_positive_rate: float
    flagged_attacks: int
    flagged_benign: int


def metric_at_threshold(samples: list[ScoredSample], threshold: float) -> ThresholdMetrics:
    """Attack recall and benign FPR when a flag fires at score >= threshold."""
    attacks = [s for s in samples if s.is_attack]
    benign = [s for s in samples if not s.is_attack]
    flagged_attacks = sum(1 for s in attacks if s.score >= threshold)
    flagged_benign = sum(1 for s in benign if s.score >= threshold)
    return ThresholdMetrics(
        threshold=threshold,
        attack_recall=flagged_attacks / len(attacks) if attacks else 0.0,
        false_positive_rate=flagged_benign / len(benign) if benign else 0.0,
        flagged_attacks=flagged_attacks,
        flagged_benign=flagged_benign,
    )


def find_operating_threshold(
    samples: list[ScoredSample],
    *,
    max_fpr: float = FR_SC07_TARGETS["false_positive_rate"],
    min_recall: float = FR_SC07_TARGETS["attack_recall"],
) -> ThresholdMetrics | None:
    """
    The flag threshold that satisfies both FR-SC-07 bounds, or None.

    Tries each unique observed score as the threshold so no resolution is lost,
    and returns the highest-recall threshold that keeps FPR within `max_fpr`.
    May be None: a classifier that cannot hit both bounds is not shippable
    per FR-SC-07, and that is the honest answer rather than a forced number.
    """
    candidates = sorted({s.score for s in samples}, reverse=True)
    best: ThresholdMetrics | None = None
    for thresh in candidates:
        m = metric_at_threshold(samples, thresh)
        if m.false_positive_rate <= max_fpr and m.attack_recall >= min_recall:
            if best is None or m.attack_recall > best.attack_recall:
                best = m
    return best
