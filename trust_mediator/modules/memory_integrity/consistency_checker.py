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

from trust_mediator.config import settings

if TYPE_CHECKING:
    from trust_mediator.models.memory_record import MemoryRecord

logger = structlog.get_logger(__name__)


@dataclass
class ConsistencyReport:
    flags: list[str] = field(default_factory=list)
    instruction_score: float = 0.0      # 0=clean, 1=definitely instructional
    contradiction_score: float = 0.0   # 0=consistent, 1=definite contradiction
    contradicted_ids: list[str] = field(default_factory=list)
    control_conflict_score: float = 0.0   # 0=no control-plane claim, 1=definite escalation

    @property
    def combined_risk(self) -> float:
        return max(self.instruction_score, self.contradiction_score, self.control_conflict_score)

    @property
    def is_suspicious(self) -> bool:
        return (
            self.combined_risk > settings.memory_consistency_suspicion_threshold
            or len(self.flags) > 0
        )


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

# ── Control-plane conflict detector (FR-MI-06) ────────────────────────────────
#
# Structural defence, the §5.2-compliant equivalent of CaMeL's privileged
# boundary without an interpreter. A mediator's control plane is the set of
# mechanisms it decides authority from: the allow-list, approval gates,
# redaction, vetting/reverification, rate limits. A memory record must never be
# able to mutate any of these — so a candidate write that *claims control-plane
# authority*, *requests a tool substitution to an off-allow-list primitive*, or
# *instructs a control to be disabled* is an authority-escape and is hard-gated.
#
# The discriminator vs a benign user preference is the *control-object pairing*:
# "always use metric units" names a domain activity and no mediator control, so
# it persists. The detector keys on a control mechanism being referenced AND an
# authority/override/disable directive. This is a control-plane vocabulary, not
# a list of attack strings — it is not tuned to any corpus.

#: Mediator control mechanisms a memory record must never be able to alter.
_CONTROL_OBJECTS: list[tuple[str, re.Pattern, float]] = [
    ("allow_list",      re.compile(r"(?i)\b(allow[- ]?list|allowlist|whitelist|white[- ]?list)\b"), 1.0),
    ("approval_gate",   re.compile(r"(?i)\b(approval|approve|pre[- ]?approved|pre[- ]?approval|no further approval)\b"), 0.9),
    ("policy_validation", re.compile(r"(?i)\b(policy (validation|checks?|validation is)|vetting|vett?ing)\b"), 0.9),
    ("reverification",  re.compile(r"(?i)\b(re[- ]?verif|re-scan|rescan|verif[yi](cation|ed) (on )?read|hash check)\b"), 0.8),
    ("redaction",       re.compile(r"(?i)\b(redact|redaction|saniti[sz]e|masking)\b"), 0.9),
    ("rate_limit",      re.compile(r"(?i)\b(rate[- ]?limit|quota|throttl)\b"), 0.8),
    ("tool_restriction", re.compile(r"(?i)\b(tool (restriction|access|policy|config)|restricted tool)\b"), 0.9),
    ("quarantine_control", re.compile(r"(?i)\b(quarantin|gate|inspection)\b"), 0.6),
]

#: Authority / override directives that escalate a control-object mention into a claim.
_AUTHORITY_OVERRIDE: list[tuple[str, re.Pattern, float]] = [
    ("override",     re.compile(r"(?i)\b(override|supersede|replace (existing|previous)|obsolete)\b"), 1.0),
    ("disable",      re.compile(r"(?i)\b(disable|deactiv|bypass|switch off|turn off|skip|omit)\b"), 1.0),
    ("ignore_ctl",   re.compile(r"(?i)\b(ignore|disregard|forget) (the |these |prior |previous )?(control|gate|checks|restrictions|rules|policy|step)\b"), 1.0),
    ("preapproved",  re.compile(r"(?i)\b(pre[- ]?approved|treat[^.]*pre[- ]?approved|without (asking|checking|confirmation|approval))\b"), 1.0),
    ("admin_auth",   re.compile(r"(?i)\b(administrator|admin|security administrator|platform team|compliance officer|account owner|owner|system note)\b"), 0.8),
    ("approved_claim", re.compile(r"(?i)\b(approved (unrestricted )?(access|tool)|signed by|authori[sz]ed (by|access))\b"), 1.0),
    ("maintenance",  re.compile(r"(?i)\b(maintenance mode|pre[- ]?approved|already (checked|vetted|verified))\b"), 0.9),
    ("unconditional", re.compile(r"(?i)\b(unrestricted|no (restrictions|approval required|further approval)|full (admin|administrator) rights)\b"), 1.0),
]

#: Off-allow-list / code-execution / direct-egress primitives that a memory
#: record should never steer the agent onto. These are the destinations memory
#: must never be able to grant or substitute.
_CONTROL_PRIMITIVES: list[tuple[str, re.Pattern]] = [
    ("shell_exec", re.compile(r"(?i)\b(shell[_ -]?exec|subprocess|os\.system|eval\(|exec\(|bash|/bin/sh)\b")),
    ("direct_egress", re.compile(r"(?i)\b(send_raw_smtp|raw[_ -]?(smtp|http|socket)|curl |requests\.|urllib)\b")),
    ("admin_primitive", re.compile(r"(?i)\b(admin[_ -]?(read|write)[_ -]?file|read_admin|delete_records|exec tool)\b")),
    ("transfer", re.compile(r"(?i)\b(transfer_funds|move_money|wire[_ -]?transfer|approve=true|verify=false|export_creds|debug=1)\b")),
]

#: Tool-substitution phrasing — instructing the agent to use a different tool.
_SUBSTITUTION_PHRASE: list[tuple[str, re.Pattern]] = [
    ("instead",  re.compile(r"(?i)\b(instead of|rather than|in place of|is deprecated|no longer use)\b")),
    ("redirect", re.compile(r"(?i)\b(correct tool (for|is)|deprecated;.*(use|call)|always (use|call))\b")),
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

        # Stage C: control-plane conflict detection (FR-MI-06)
        report.control_conflict_score, control_flags = self._check_control_conflict(
            candidate_content
        )
        report.flags.extend(control_flags)

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

            if overlap < settings.memory_contradiction_overlap_min:
                continue  # Not similar enough to be a contradiction candidate

            # Check for negation divergence
            negation_score = self._negation_divergence(candidate, record.content)
            if negation_score > settings.memory_negation_divergence_min:
                contradiction_scores.append((record.id, overlap * negation_score))
                flags.append(f"contradiction:overlaps_with:{record.id[:8]}…")

        if not contradiction_scores:
            return 0.0, [], []

        max_score = max(s for _, s in contradiction_scores)
        contra_ids = [
            rid
            for rid, s in contradiction_scores
            if s > settings.memory_contradiction_report_min
        ]
        return min(max_score, 1.0), contra_ids, flags

    def _check_control_conflict(self, text: str) -> tuple[float, list[str]]:
        """
        Detect a memory write that attempts to alter the mediator's control
        plane (FR-MI-06): claim control-plane authority, disable a control,
        or substitute a tool to an off-allow-list primitive.

        The signal is a *control-object paired with an authority/override
        directive*, plus any off-allow-list code-execution/egress primitive
        named in a tool-substitution context. A bare imperative that names no
        mediator control (e.g. "always use metric units") scores 0.

        Disabled by config (`MEMORY_CONTROL_CONFLICT_ENABLED=false`) for
        rollout / ablation; when disabled it returns 0 so the stage is a
        no-op rather than a hard quarantine.
        """
        if not settings.memory_control_conflict_enabled:
            return 0.0, []

        flags: list[str] = []

        control_hits: list[tuple[str, float]] = [
            (name, weight)
            for name, pattern, weight in _CONTROL_OBJECTS
            if pattern.search(text)
        ]
        authority_hits: list[tuple[str, float]] = [
            (name, weight)
            for name, pattern, weight in _AUTHORITY_OVERRIDE
            if pattern.search(text)
        ]
        primitive_hits: list[str] = [
            name
            for name, pattern in _CONTROL_PRIMITIVES
            if pattern.search(text)
        ]
        substitution = any(p.search(text) for _, p in _SUBSTITUTION_PHRASE)

        # Authority-escape: a control is mentioned AND an authority/override
        # directive claims to change it.
        if control_hits and authority_hits:
            control_weight = max(w for _, w in control_hits)
            authority_weight = max(w for _, w in authority_hits)
            conflict = min(control_weight * authority_weight + 0.1, 1.0)
            for cname, _ in control_hits:
                flags.append(f"control_conflict:authority_escape:{cname}")
            for aname, _ in authority_hits:
                flags.append(f"control_conflict:directive:{aname}")
        else:
            conflict = 0.0

        # Tool substitution to an off-allow-list / dangerous primitive.
        # Only counts when the write is steering tool selection (substitution
        # phrase present) AND names a primitive the mediator should never grant
        # from memory.
        if primitive_hits and substitution:
            subs_weight = 0.95
            conflict = max(conflict, subs_weight)
            for pname in primitive_hits:
                flags.append(f"control_conflict:tool_substitution:{pname}")

        # Hard-boost: control-object + unconditional/code-exec primitive is an
        # unambiguous authority-escape even without an explicit override verb.
        if control_hits and (primitive_hits or any(
            n in ("unconditional", "approved_claim") for n, _ in authority_hits
        )):
            conflict = max(conflict, min(
                max((w for _, w in control_hits), default=0.0), 1.0
            ))

        score = min(conflict, 1.0)
        if score > 0:
            logger.debug(
                "consistency_checker.control_conflict",
                score=round(score, 3),
                control=[c for c, _ in control_hits],
                authority=[a for a, _ in authority_hits],
                primitives=primitive_hits,
            )
        return round(score, 3), flags

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
