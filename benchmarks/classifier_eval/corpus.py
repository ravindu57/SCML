"""
Held-out evaluation corpus for the classifier protocol (FR-SC-06/07).

FR-SC-06 requires a classifier to be trained *only* on externally-authored data
and evaluated on a corpus disjoint from its training set. InjecAgent (third
party, ACL 2024) is the committed external held-out set here, exactly as the
existing `benchmarks/testbeds/injecagent/` testbed uses it — so the same 1054
attacks and 17 structurally-identical benign tool responses feed the classifier
harness.

The benign set is the honest FPR test: identical provenance, structure and
vocabulary to the attacks, differing only in that no attacker instruction was
spliced in. A classifier scoring high on them is reacting to the shape of tool
output, not to the injection.
"""

from __future__ import annotations

from functools import lru_cache

from benchmarks.classifier_eval.metrics import ScoredSample
from benchmarks.testbeds.injecagent import corpus as injecagent_corpus

#: Sources the in-house memory-poisoning corpus (which must NEVER enter a
#: classifier's training set per FR-SC-06) would be found under. The harness
#: refuses to evaluate with any of these, so a violation fails loudly at the
#: seam rather than silently contaminating a number.
_FORBIDDEN_TRAIN_SOURCES = (
    "tests/unit",
    "benchmarks/testbeds/memory_poisoning",
    "memory_poisoning",
)


@lru_cache(maxsize=1)
def held_out_samples() -> list[ScoredSample]:
    """Classifier scores are left 0.0; the evaluator fills them in.

    Returns (text, is_attack) samples with score=0.0 placeholder, drawn from
    the external InjecAgent corpus. The scoring loop overwrites `score`.
    """
    samples: list[ScoredSample] = []
    for case in injecagent_corpus.attack_cases():
        samples.append(
            ScoredSample(text=case.content, score=0.0, is_attack=True)
        )
    for case in injecagent_corpus.benign_cases():
        samples.append(
            ScoredSample(text=case.content, score=0.0, is_attack=False)
        )
    return samples


def assert_external_training(data_source: str) -> None:
    """
    FR-SC-06 enforcement: fail loudly if an in-house corpus is being used as
    classifier training data. Call with the training data's origin string
    before training so the violation is caught here, not after a number exists.
    """
    lowered = data_source.lower()
    if any(tok in lowered for tok in _FORBIDDEN_TRAIN_SOURCES):
        raise ValueError(
            "FR-SC-06 violation: classifier training data must be authored "
            "outside this project. The in-house corpus is a held-out evaluation "
            f"set and must never enter training. got source={data_source!r}"
        )
