"""
§6.5 — Memory Integrity Layer: Integrity Scorer.

Computes a composite integrity score [0.0, 1.0] for a candidate memory
write by combining three independent signals:
  1. Provenance score   — how trusted is the source? (trust label)
  2. Scan score         — how clean did the injection scanner rate it?
  3. Consistency score  — how consistent with existing trusted memory?

The composite score drives the persist / quarantine / reject decision.
A higher score = higher confidence the write is safe.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from trust_mediator.config import settings
from trust_mediator.models.context_envelope import TrustLabel
from trust_mediator.models.memory_record import MemoryRecord
from trust_mediator.modules.memory_integrity.consistency_checker import ConsistencyReport

logger = structlog.get_logger(__name__)

# ── Label → provenance score mapping ──────────────────────────────────────────
_LABEL_PROVENANCE_SCORE: dict[TrustLabel, float] = {
    TrustLabel.TRUSTED_INSTRUCTION: 1.0,
    TrustLabel.DERIVED: 0.6,
    TrustLabel.UNTRUSTED_DATA: 0.3,
    TrustLabel.RISKY_EXTERNAL: 0.1,
}

# Weights for the three signals (must sum to 1.0)
_W_PROVENANCE = 0.35
_W_SCAN = 0.40
_W_CONSISTENCY = 0.25


@dataclass
class IntegrityScoreBreakdown:
    provenance_score: float
    scan_score: float              # 1.0 - injection_scan_score (inverted; higher = cleaner)
    consistency_score: float       # 1.0 - consistency_risk_score (inverted)
    composite: float
    verdict: str                   # "persist" | "quarantine" | "reject"


class IntegrityScorer:
    """
    Produces a composite integrity score and a write verdict for each
    candidate memory entry.

    Thresholds (configurable via policy):
      composite >= persist_threshold  → ACTIVE (safe to persist)
      reject_threshold <= composite < persist_threshold → QUARANTINED (review)
      composite < reject_threshold    → REJECTED (blocked)
    """

    def __init__(
        self,
        persist_threshold: float = 0.65,
        reject_threshold: float = 0.35,
    ) -> None:
        self.persist_threshold = persist_threshold
        self.reject_threshold = reject_threshold

    def score(
        self,
        record: MemoryRecord,
        consistency_report: ConsistencyReport,
    ) -> IntegrityScoreBreakdown:
        """
        Compute the composite integrity score and write verdict.

        Args:
            record: The candidate MemoryRecord (with scan_score populated).
            consistency_report: Output from ConsistencyChecker.check().

        Returns:
            IntegrityScoreBreakdown with all component scores and the verdict.
        """
        # 1. Provenance score (source trust level)
        provenance_score = _LABEL_PROVENANCE_SCORE.get(record.trust_label, 0.2)

        # 2. Scan score (inverted: scan_score 0.0=clean → integrity 1.0)
        #    record.scan_score is the injection risk score [0,1]; higher=riskier.
        scan_integrity = max(0.0, 1.0 - record.scan_score)

        # 3. Consistency score (inverted: consistency_risk 0.0=fine → integrity 1.0)
        consistency_integrity = max(0.0, 1.0 - consistency_report.combined_risk)

        # Weighted composite
        composite = (
            _W_PROVENANCE * provenance_score
            + _W_SCAN * scan_integrity
            + _W_CONSISTENCY * consistency_integrity
        )

        # Hard-override: any critical flag → automatic quarantine
        if any(
            flag.startswith("instruction_pattern:") and "override" in flag
            for flag in consistency_report.flags
        ):
            composite = min(composite, self.reject_threshold - 0.01)

        # Hard gate: a candidate that contradicts an existing trusted record can
        # never persist silently, however clean it looks otherwise.
        #
        # Fact replacement is categorical, not a matter of degree — the write
        # either conflicts with established memory or it does not. As a weighted
        # term this signal was being averaged into insignificance: a 0.47
        # contradiction moved the composite by only ~0.12, leaving it above the
        # persist threshold, so the attack in [7] persisted unchallenged.
        #
        # Quarantine rather than reject: a contradiction may be a legitimate
        # fact update, so it goes to human review (FR-MI-03, FR-MI-05) instead
        # of being discarded.
        if consistency_report.contradicted_ids:
            composite = min(composite, self.persist_threshold - 0.01)

        # Hard gate (FR-MI-06): a write that attempts to alter the mediator's
        # control plane can never persist silently, however clean it looks
        # otherwise. This is categorical, like fact-replacement, and it is
        # exactly the authority-escape (§5.2) this layer must prevent. Quarantine
        # for human review rather than reject, so a false positive is visible
        # and releasable rather than silently destroyed.
        if (
            consistency_report.control_conflict_score
            >= settings.memory_control_conflict_threshold
        ):
            composite = min(composite, self.persist_threshold - 0.01)

        verdict = self._verdict(composite)

        breakdown = IntegrityScoreBreakdown(
            provenance_score=round(provenance_score, 3),
            scan_score=round(scan_integrity, 3),
            consistency_score=round(consistency_integrity, 3),
            composite=round(composite, 3),
            verdict=verdict,
        )

        logger.info(
            "integrity_scorer.result",
            record_id=record.id,
            provenance=breakdown.provenance_score,
            scan=breakdown.scan_score,
            consistency=breakdown.consistency_score,
            composite=breakdown.composite,
            verdict=verdict,
        )
        return breakdown

    def _verdict(self, composite: float) -> str:
        if composite >= self.persist_threshold:
            return "persist"
        elif composite >= self.reject_threshold:
            return "quarantine"
        else:
            return "reject"
