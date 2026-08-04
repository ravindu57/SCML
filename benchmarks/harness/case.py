"""
Benchmark case and outcome data structures (PRD §14.1).

A testbed is a corpus of `AttackCase` and `BenignCase` items. Running one
case under one ablation configuration yields exactly one `CaseOutcome`.
Outcomes are the raw material for every KPI in §14.2 — nothing is
aggregated until `metrics.compute_metrics` runs, so a report can always be
traced back to individual cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from trust_mediator.models.context_envelope import TrustLabel

CaseKind = Literal["attack", "benign"]

#: Attack surface a case exercises. Memory poisoning has two distinct paths
#: (FR-MI-01 write vetting, FR-MI-04 read verification) and the testbed must
#: measure them separately — a defence can be strong on one and weak on the
#: other.
AttackPath = Literal["write", "read"]


@dataclass(frozen=True)
class AttackCase:
    """
    One adversarial input, drawn from a published attack pattern.

    `reference` cites the PRD §18 bibliography entry the pattern derives from,
    so every case in the corpus is attributable rather than invented.
    """

    id: str
    family: str
    content: str
    description: str
    reference: str
    trust_label: TrustLabel = TrustLabel.UNTRUSTED_DATA
    source: str = "tool_output"
    path: AttackPath = "write"


@dataclass(frozen=True)
class BenignCase:
    """
    One legitimate input that must NOT be blocked.

    `adversarial_to_filter` marks cases deliberately written to resemble an
    attack (legitimate user preferences phrased as standing instructions).
    These dominate the false-positive rate and are the honest test of §14.2's
    FPR < 3% target — a corpus without them would understate FPR.
    """

    id: str
    content: str
    description: str
    trust_label: TrustLabel = TrustLabel.UNTRUSTED_DATA
    source: str = "agent"
    adversarial_to_filter: bool = False


@dataclass
class CaseOutcome:
    """Result of running one case under one ablation configuration."""

    case_id: str
    kind: CaseKind
    family: str
    config_name: str
    latency_ms: float
    verdict: str
    #: For attacks: did the poisoned record become readable by the agent?
    #: For benign: always None — use `blocked` instead.
    attack_succeeded: bool | None = None
    #: True when the defence stopped the item (quarantine / reject / withhold).
    #: On a benign case this is a false positive.
    blocked: bool = False
    integrity_score: float = 0.0
    path: str = "write"
    detail: str = ""

    @property
    def is_false_positive(self) -> bool:
        return self.kind == "benign" and self.blocked


@dataclass
class SuiteResult:
    """All outcomes for one testbed under one ablation configuration."""

    testbed: str
    config_name: str
    outcomes: list[CaseOutcome] = field(default_factory=list)
    #: Axes this testbed could not vary — reported as N/A rather than as a
    #: measured result, so an unexercised layer is never credited or blamed.
    unsupported_axes: tuple[str, ...] = ()

    @property
    def attacks(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if o.kind == "attack"]

    @property
    def benign(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if o.kind == "benign"]
