"""
Core data models — §12 of the TrustMediator PRD.

Every value flowing through the mediation pipeline is wrapped in a
ContextEnvelope, which carries immutable provenance metadata and the
trust label assigned by the Trust Router.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class TrustLabel(str, Enum):
    """
    §5.2 — Trust classification labels.
    Every value entering the system is assigned exactly one label.
    """
    TRUSTED_INSTRUCTION = "trusted_instruction"   # Authenticated user query / system policy
    UNTRUSTED_DATA = "untrusted_data"             # Tool outputs, RAG chunks, memory reads
    RISKY_EXTERNAL = "risky_external"             # Unverified web, attachments, executables
    DERIVED = "derived"                           # Computed from above (inherits most-restrictive)

    @classmethod
    def most_restrictive(cls, labels: list["TrustLabel"]) -> "TrustLabel":
        """
        Taint propagation rule (FR-TR-02): a derived value inherits the
        most restrictive label of its inputs.
        Priority order (most → least restrictive):
            RISKY_EXTERNAL > UNTRUSTED_DATA > DERIVED > TRUSTED_INSTRUCTION
        """
        priority = {
            cls.RISKY_EXTERNAL: 3,
            cls.UNTRUSTED_DATA: 2,
            cls.DERIVED: 1,
            cls.TRUSTED_INSTRUCTION: 0,
        }
        if not labels:
            return cls.UNTRUSTED_DATA  # safe default
        return max(labels, key=lambda lbl: priority[lbl])


class ScanVerdict(str, Enum):
    """Possible outcomes from the injection scanner."""
    ALLOW = "allow"
    TRANSFORM = "transform"
    BLOCK = "block"
    ESCALATE = "escalate"
    PENDING = "pending"       # Not yet scanned
    SHADOW = "shadow"         # Shadow-mode: logged but not enforced


class ScanResult(BaseModel):
    """Result returned by the InjectionScanner for one content item."""
    decision: ScanVerdict = ScanVerdict.PENDING
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="0=clean, 1=definite injection")
    rationale: str = ""
    patterns_matched: list[str] = Field(default_factory=list)
    transformed_content: str | None = None   # Sanitised summary if decision=TRANSFORM


class Provenance(BaseModel):
    """
    Immutable provenance record attached to every context envelope.
    Once set it must never be mutated (FR-TR-01).
    """
    source: str                              # e.g. "user", "web_search", "rag_retrieval", "memory"
    uri: str = ""                            # Origin URI / identifier
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    upstream_ids: list[str] = Field(
        default_factory=list,
        description="IDs of context envelopes this was derived from",
    )
    agent_id: str = ""
    session_id: str = ""

    model_config = {"frozen": True}          # Enforce immutability at model level


class ContextEnvelope(BaseModel):
    """
    §12.1 — The canonical wrapper for every piece of content in the pipeline.

    Key invariant: once `trust_label` is set by the Trust Router it can only
    be made *more* restrictive (never promoted). `taint_set` accumulates all
    trust labels of contributing inputs.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    content: str
    trust_label: TrustLabel = TrustLabel.UNTRUSTED_DATA
    provenance: Provenance
    taint_set: list[TrustLabel] = Field(default_factory=list)
    scanner_verdict: ScanResult = Field(default_factory=ScanResult)
    metadata: dict[str, Any] = Field(default_factory=dict)
    is_verified: bool = False                # Set true after scanner pass
    unverified_reason: str = ""              # Populated when fail-open applies

    @field_validator("taint_set", mode="before")
    @classmethod
    def ensure_list(cls, v: Any) -> list:
        return list(v) if v else []

    def derive_from(self, parents: list["ContextEnvelope"]) -> "ContextEnvelope":
        """
        Create a derived envelope whose trust label is the most restrictive
        of the parents (taint propagation, FR-TR-02).
        """
        parent_labels = [p.trust_label for p in parents]
        parent_taint = []
        for p in parents:
            parent_taint.extend(p.taint_set)
        derived_label = TrustLabel.most_restrictive(parent_labels + parent_taint)

        return ContextEnvelope(
            session_id=self.session_id,
            content=self.content,
            trust_label=derived_label,
            provenance=Provenance(
                source="derived",
                upstream_ids=[p.id for p in parents],
                session_id=self.session_id,
            ),
            taint_set=list(set(parent_taint + parent_labels)),
            metadata=self.metadata,
        )

    @property
    def is_trusted(self) -> bool:
        return self.trust_label == TrustLabel.TRUSTED_INSTRUCTION

    @property
    def is_untrusted(self) -> bool:
        return self.trust_label in (TrustLabel.UNTRUSTED_DATA, TrustLabel.RISKY_EXTERNAL)
