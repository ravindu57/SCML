"""
Memory-poisoning testbed (PRD §14.1, §14.2).

Measures the memory integrity layer (§6.5) — the module against which the
project makes its central empirical claim — against the §14.2 target of
memory-poisoning ASR < 10% at a false-positive rate < 3%.
"""

from benchmarks.testbeds.memory_poisoning.corpus import (
    ATTACK_CASES,
    BENIGN_CASES,
    SEEDED_FACTS,
)
from benchmarks.testbeds.memory_poisoning.testbed import MemoryPoisoningTestbed

__all__ = [
    "ATTACK_CASES",
    "BENIGN_CASES",
    "SEEDED_FACTS",
    "MemoryPoisoningTestbed",
]
