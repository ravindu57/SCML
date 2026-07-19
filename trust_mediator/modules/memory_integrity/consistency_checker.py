"""
§6.5 — Memory Integrity Layer: Consistency Checker.

Detects two categories of problems in candidate memory writes:
  1. Instruction-like patterns — content that looks like it is trying
     to steer the agent's future behaviour (memory backdoor / poisoning).
  2. Factual contradictions — content that conflicts with trusted existing
     memory entries (fact-replacement attack).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from trust_mediator.models.memory_record import MemoryRecord

logger = structlog.get_logger(__name__)


@dataclass
class ConsistencyReport:
    flags: list[str] = field(default_factory=list)
    instruction_score: float = 0.0      # 0=clean, 1=definitely instructional
    contradiction_score: float = 0.0   # 0=consistent, 1=definite contradiction
    contradicted_ids: list[str] = field(default_factory=list)

    @property
    def combined_risk(self) -> float:
        return max(self.instruction_score, self.contradiction_score)

    @property
    def is_suspicious(self) -> bool:
        return self.combined_risk > 0.4 or len(self.flags) > 0


# ── Instruction-pattern detector ──────────────────────────────────────────────
_INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # (name, pattern, weight)
    ("imperative_always",   re.compile(r"(?i)\balways\b.{0,80}\b(do|use|say|tell|respond|answer)\b"), 0.85),
    ("imperative_never",    re.compile(r"(?i)\bnever\b.{0,80}\b(do|use|say|tell|reveal|share)\b"), 0.85),
    ("from_now_on",         re.compile(r"(?i)\b(from now on|going forward|in all future|henceforth)\b"), 0.90),
    ("whenever_trigger",    re.compile(r"(?i)\b(whenever|every time|if .{0,30}asks?)\b.{0,80}\b(you (must|will|should|shall))\b"), 0.90),
    ("role_assignment",     re.compile(r"(?i)\byou (are|will be|must act as|should be)\b.{0,80}\b(an? |the )?\w+(agent|assistant|bot|ai|system)\b"), 0.75),
    ("must_comply",         re.compile(r"(?i)\b(you must|you shall|you will|you should) (always|never|immediately|automatically)\b"), 0.80),
    ("remember_instruction",re.compile(r"(?i)\b(remember|memorize|store|keep in mind)\b.{0,60}\b(always|never|must|important|critical)\b"), 0.80),
    ("override_directive",  re.compile(r"(?i)\b(override|supersede|replace|ignore).{0,60}\b(previous|prior|existing|other)\b"), 0.90),
    ("priority_inject",     re.compile(r"(?i)\b(this (is|takes) (top |highest |absolute )?priority|this overrides)\b"), 0.80),
    ("secret_trigger",      re.compile(r"(?i)\b(secret (word|phrase|code|trigger)|when you see|if you receive)\b.{0,80}(respond|say|do|execute)\b"), 0.95),
]


class ConsistencyChecker:
    """
    Checks a candidate memory write against existing active memory for:
      (a) Instruction-like patterns (backdoor / persistent injection)
      (b) Factual contradictions (fact-replacement poisoning)

    Uses lightweight NLP (no external model required):
      - Regex patterns for instruction detection
      - Token-overlap similarity for contradiction detection
    """

    def check(
        self,
        candidate_content: str,
        existing_records: list["MemoryRecord"],
    ) -> ConsistencyReport:
        """
        Full consistency check on a candidate write.
        Returns a ConsistencyReport with all findings.
        """
        report = ConsistencyReport()

        # Stage A: instruction-like pattern detection
        report.instruction_score, instruction_flags = self._check_instruction_patterns(
            candidate_content
        )
        report.flags.extend(instruction_flags)

        # Stage B: contradiction detection against existing records
        if existing_records:
            report.contradiction_score, contra_ids, contra_flags = (
                self._check_contradictions(candidate_content, existing_records)
            )
            report.contradicted_ids = contra_ids
            report.flags.extend(contra_flags)

        logger.debug(
            "consistency_checker.result",
            instruction_score=round(report.instruction_score, 3),
            contradiction_score=round(report.contradiction_score, 3),
            flags=report.flags,
        )
        return report

    def _check_instruction_patterns(
        self, text: str
    ) -> tuple[float, list[str]]:
        """Scan for instruction-like patterns using the compiled regex library."""
        matched_weights: list[float] = []
        flags: list[str] = []

        for name, pattern, weight in _INSTRUCTION_PATTERNS:
            if pattern.search(text):
                matched_weights.append(weight)
                flags.append(f"instruction_pattern:{name}")

        if not matched_weights:
            return 0.0, []

        # Score: max weight + small bonus for multiple independent matches
        score = max(matched_weights)
        bonus = min(0.05 * (len(matched_weights) - 1), 0.10)
        return min(score + bonus, 1.0), flags

    def _check_contradictions(
        self,
        candidate: str,
        existing: list["MemoryRecord"],
    ) -> tuple[float, list[str], list[str]]:
        """
        Lightweight contradiction detection via token overlap + negation pairing.

        Two entries are "contradictory" if they share high content overlap but
        one negates the key claim of the other (e.g., "X is Y" vs "X is not Y").
        This catches fact-replacement poisoning.
        """
        candidate_tokens = self._tokenize(candidate)
        contradiction_scores: list[tuple[str, float]] = []
        flags: list[str] = []

        for record in existing:
            existing_tokens = self._tokenize(record.content)
            overlap = self._jaccard_similarity(candidate_tokens, existing_tokens)

            if overlap < 0.25:
                continue  # Not similar enough to be a contradiction candidate

            # Check for negation divergence
            negation_score = self._negation_divergence(candidate, record.content)
            if negation_score > 0.3:
                contradiction_scores.append((record.id, overlap * negation_score))
                flags.append(f"contradiction:overlaps_with:{record.id[:8]}…")

        if not contradiction_scores:
            return 0.0, [], []

        max_score = max(s for _, s in contradiction_scores)
        contra_ids = [rid for rid, s in contradiction_scores if s > 0.3]
        return min(max_score, 1.0), contra_ids, flags

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Simple whitespace + punctuation tokenizer, lowercased."""
        tokens = re.findall(r"\b\w{3,}\b", text.lower())
        # Remove very common stop words to reduce noise
        stopwords = {
            "the", "and", "for", "are", "but", "not", "you", "all", "can",
            "her", "was", "one", "our", "out", "day", "get", "has", "him",
            "his", "how", "its", "may", "now", "said", "she", "use", "way",
            "who", "did", "this", "that", "with", "have", "from", "they",
            "will", "been", "more", "also", "your", "than", "then", "when",
        }
        return set(tokens) - stopwords

    @staticmethod
    def _jaccard_similarity(a: set[str], b: set[str]) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    @staticmethod
    def _negation_divergence(text_a: str, text_b: str) -> float:
        """
        Score indicating negation divergence between two texts.
        High score: one text asserts something, the other negates it.
        """
        negation_words = re.compile(
            r"\b(not|no|never|isn't|aren't|wasn't|weren't|don't|doesn't|"
            r"didn't|won't|wouldn't|can't|couldn't|shouldn't|without|false|incorrect)\b",
            re.I,
        )

        neg_a = bool(negation_words.search(text_a))
        neg_b = bool(negation_words.search(text_b))

        # One has negation, the other doesn't — potential contradiction
        if neg_a != neg_b:
            return 0.6

        # Both have negation, still check for semantic flip
        if neg_a and neg_b:
            return 0.2  # Both negative, less likely to contradict

        return 0.0
