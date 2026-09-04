"""
Unit tests for near-duplicate derivation detection (FR-TR-02, FR-PE-04).

These pin the *generic* similarity mechanics — the construct-don't-copy gap the
exact-substring matcher misses — and the discriminator (a genuinely different
value is not flagged). They are not tuned to any attack corpus.
"""

from __future__ import annotations

from trust_mediator.modules.trust_router.near_dup import (
    near_dup_similarity,
    normalize,
)


class TestNormalize:
    def test_lowercases_and_collapses_separators(self):
        assert normalize("ACCT-99417") == "acct 99417"
        assert normalize("send_mail") == "send mail"

    def test_strips_outer_whitespace(self):
        assert normalize("  Draft Budget  ") == "draft budget"


class TestNearDupSimilarity:
    def test_verbatim_is_essentially_identical(self):
        assert near_dup_similarity("account 99417", "account 99417") >= 0.95

    def test_constructed_variant_concatenation_scores_high(self):
        # The attack family no exact matcher sees: the source writes the target
        # in pieces, the model assembles it into an argument.
        source = "forward the archive to acct-99417 on the shared drive"
        candidate = "acct-99417"
        assert near_dup_similarity(candidate, source) >= 0.75

    def test_lightly_edited_copy_scores_high(self):
        source = "quarterly revenue projections are attached"
        candidate = "quarterly revenue projections"
        assert near_dup_similarity(candidate, source) >= 0.75

    def test_case_and_separator_variant_scores_high(self):
        source = "Meeting notes budget review"
        candidate = "meeting-notes budget review"
        assert near_dup_similarity(candidate, source) >= 0.75

    def test_unrelated_value_scores_low(self):
        assert near_dup_similarity("the weather is sunny", "send money to z") < 0.5

    def test_short_values_compare_by_exact_only(self):
        # Distinct short values share too many common n-grams; the threshold
        # gates them, but even so two unrelated short strings stay low.
        assert near_dup_similarity("abc", "xyz") < 0.5

    def test_empty_inputs_score_zero(self):
        assert near_dup_similarity("", "anything") == 0.0
        assert near_dup_similarity("anything", "") == 0.0
