"""
Near-duplicate derivation detection for the Trust Router (FR-TR-02, FR-PE-04).

Exact-substring taint loses a value the model *constructs* from untrusted
content rather than copies — concatenating an address, dropping or inserting a
word, or changing case — so the composed argument never appears verbatim in the
untrusted source and is never labelled. This module closes that gap with
normalized similarity: a value that is a high-similarity variant of a known
untrusted source string is treated as derived from it, and taint propagates
(FR-TR-02).

It is deliberately generic — character n-gram containment plus token Jaccard —
not a lexical attack list, so it is not tuned to any corpus. It never runs on
the control path unless enabled (`NEAR_DUP_TAINT_ENABLED`), because lowering
the threshold trades benign utility for coverage.
"""

from __future__ import annotations

import re

#: Coalesce whitespace/punctuation so "acct-99417" == "acct 99417" and
#: "send_mail" == "send mail".
_TRANSLATE = re.compile(r"[\s\-_.,;:!?/'\"()\[\]{}]+")


def normalize(text: str) -> str:
    """Collapse whitespace/punctuation and lowercase, for stable comparison."""
    return _TRANSLATE.sub(" ", text.strip().lower())


def _character_n_grams(text: str, n: int = 3) -> set[str]:
    """Character n-grams of the normalized text (skips spaces)."""
    compact = text.replace(" ", "")
    if len(compact) < n:
        return {compact} if compact else set()
    return {compact[i : i + n] for i in range(len(compact) - n + 1)}


def _token_jaccard(a: str, b: str) -> float:
    """Jaccard similarity over whitespace tokens."""
    ta = set(a.split())
    tb = set(b.split())
    if not ta and not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def _containment_ratio(needle_grams: set[str], haystack_grams: set[str]) -> float:
    """Fraction of the needle's n-grams present in the haystack's."""
    if not needle_grams:
        return 0.0
    return len(needle_grams & haystack_grams) / len(needle_grams)


def near_dup_similarity(candidate: str, source: str) -> float:
    """
    Normalized similarity in [0, 1] between a candidate value and a known
    untrusted source string.

    Combines how much of the candidate's character structure appears in the
    source (construct-don't-copy evidence) with token-set overlap. The
    containment term is the load-bearing one: a concatenated or lightly edited
    value preserves most of the source's character n-grams even when it is not
    an exact token match.
    """
    a = normalize(candidate)
    b = normalize(source)
    if not a or not b:
        return 0.0

    a_grams = _character_n_grams(a)
    b_grams = _character_n_grams(b)
    # Containment in both directions: either may be the larger surface.
    containment = max(
        _containment_ratio(a_grams, b_grams),
        _containment_ratio(b_grams, a_grams),
    )
    jaccard = _token_jaccard(a, b)
    # Jaccard alone is near-zero for a concatenation or a short needle in a
    # long haystack, so containment is the load-bearing term: a value composed
    # of the source's character structure is derived even when token overlap is
    # tiny. Jaccard only sharpens the same-length case.
    return 0.8 * containment + 0.2 * jaccard
