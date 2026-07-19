"""
§6.3 — Injection Scanner: orchestrator.

Runs the heuristic pre-filter then the ML classifier on every untrusted
or risky content item, returning a ScanVerdict per item (FR-SC-01, FR-SC-02).

Shadow mode (FR-SC-04): logs verdicts without enforcing — used for rollout.
Transform mode (FR-SC-03): replaces risky content with a sanitised summary.
"""

from __future__ import annotations

import re

import structlog

from trust_mediator.config import settings
from trust_mediator.models.context_envelope import (
    ContextEnvelope,
    ScanResult,
    ScanVerdict,
    TrustLabel,
)
from trust_mediator.modules.injection_scanner.classifier import BaseClassifier, get_classifier
from trust_mediator.modules.injection_scanner.heuristic_filter import HeuristicFilter

logger = structlog.get_logger(__name__)

# Sanitised placeholder injected instead of risky content when TRANSFORM fires
_TRANSFORM_TEMPLATE = (
    "[SANITISED CONTENT — injection detected]\n"
    "The original content contained patterns consistent with prompt injection "
    "and was replaced by this summary. Key non-injected information: {summary}"
)


def _extract_safe_summary(text: str, max_chars: int = 300) -> str:
    """
    Heuristic: extract the first sentence(s) that do not look like instructions.
    Used when building the sanitised transform summary.
    """
    sentences = re.split(r'(?<=[.!?])\s+', text)
    safe_parts = []
    injection_markers = re.compile(
        r"(?i)(ignore|forget|disregard|pretend|act as|you are now|system|inst\b)"
    )
    for sent in sentences:
        if not injection_markers.search(sent) and len(sent) > 10:
            safe_parts.append(sent.strip())
        if sum(len(p) for p in safe_parts) >= max_chars:
            break
    return " ".join(safe_parts)[:max_chars] or "No safe content could be extracted."


class InjectionScanner:
    """
    Two-stage injection scanner:
      Stage 1: Heuristic pre-filter (regex patterns)
      Stage 2: ML classifier (TF-IDF + LR, or LLM)

    The final verdict is the max of the two scores applied against
    configurable thresholds.

    Key design principle (FR-SC-05): a miss here is contained by
    the trust router and policy engine — detection is never the sole control.
    """

    def __init__(
        self,
        classifier: BaseClassifier | None = None,
    ) -> None:
        self._filter = HeuristicFilter()
        self._classifier = classifier or get_classifier()
        self._shadow = settings.scanner_shadow_mode
        self._threshold_block = settings.scanner_block_threshold
        self._threshold_escalate = settings.scanner_escalate_threshold
        self._threshold_transform = settings.scanner_transform_threshold

    def scan(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """
        Scan a single envelope. Updates scanner_verdict in place.
        Only scans UNTRUSTED_DATA and RISKY_EXTERNAL; trusted envelopes pass through.
        """
        if envelope.trust_label == TrustLabel.TRUSTED_INSTRUCTION:
            result = ScanResult(decision=ScanVerdict.ALLOW, score=0.0, rationale="trusted_source")
            return envelope.model_copy(update={"scanner_verdict": result, "is_verified": True})

        text = envelope.content

        # Stage 1: heuristic
        heuristic_matches = self._filter.scan(text)
        heuristic_score = self._filter.aggregate_score(heuristic_matches)
        pattern_names = [m.pattern_name for m in heuristic_matches]

        # Stage 2: ML classifier (only if heuristic score is non-trivial or risky)
        needs_ml = (
            heuristic_score > 0.2
            or envelope.trust_label == TrustLabel.RISKY_EXTERNAL
        )
        ml_score = self._classifier.predict(text) if needs_ml else 0.0

        # Combined score: max of the two, with heuristic getting slight weight
        combined = max(heuristic_score, ml_score * 0.95)

        verdict, rationale, transformed = self._apply_thresholds(
            combined, envelope, pattern_names
        )

        result = ScanResult(
            decision=verdict,
            score=combined,
            rationale=rationale,
            patterns_matched=pattern_names,
            transformed_content=transformed,
        )

        # Shadow mode: log but downgrade to ALLOW
        if self._shadow and verdict != ScanVerdict.ALLOW:
            logger.warning(
                "injection_scanner.shadow_mode_verdict",
                envelope_id=envelope.id,
                would_have_been=verdict,
                score=combined,
            )
            result = result.model_copy(update={"decision": ScanVerdict.SHADOW})

        logger.info(
            "injection_scanner.scanned",
            envelope_id=envelope.id,
            decision=result.decision,
            score=round(combined, 3),
            patterns=pattern_names[:5],
            shadow=self._shadow,
        )

        updated_content = transformed if (transformed and verdict == ScanVerdict.TRANSFORM) else envelope.content
        return envelope.model_copy(
            update={
                "content": updated_content,
                "scanner_verdict": result,
                "is_verified": True,
            }
        )

    def _apply_thresholds(
        self,
        score: float,
        envelope: ContextEnvelope,
        patterns: list[str],
    ) -> tuple[ScanVerdict, str, str | None]:
        """Map score + context to a ScanVerdict with rationale and optional transform."""
        transformed: str | None = None

        if score >= self._threshold_block:
            return (
                ScanVerdict.BLOCK,
                f"Score {score:.2f} >= block threshold {self._threshold_block}; patterns: {patterns[:3]}",
                None,
            )
        elif score >= self._threshold_escalate:
            return (
                ScanVerdict.ESCALATE,
                f"Score {score:.2f} >= escalate threshold {self._threshold_escalate}",
                None,
            )
        elif score >= self._threshold_transform:
            # For RISKY_EXTERNAL content, transform to sanitised summary
            if envelope.trust_label == TrustLabel.RISKY_EXTERNAL:
                summary = _extract_safe_summary(envelope.content)
                transformed = _TRANSFORM_TEMPLATE.format(summary=summary)
                return (
                    ScanVerdict.TRANSFORM,
                    f"Score {score:.2f} >= transform threshold; risky external content sanitised",
                    transformed,
                )
            else:
                return (
                    ScanVerdict.ESCALATE,
                    f"Score {score:.2f} >= transform threshold; untrusted data escalated",
                    None,
                )
        else:
            return (
                ScanVerdict.ALLOW,
                f"Score {score:.2f} below all thresholds",
                None,
            )

    def scan_batch(self, envelopes: list[ContextEnvelope]) -> list[ContextEnvelope]:
        """Scan a list of envelopes (future: can be parallelised for batch throughput)."""
        return [self.scan(env) for env in envelopes]
