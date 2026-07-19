"""
Memory record data model — §12.3 of the TrustMediator PRD.

Every entry in long-term memory goes through the Memory Integrity Layer
before it can be persisted. The status field tracks the write pipeline stage.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from trust_mediator.models.context_envelope import Provenance, TrustLabel


class MemoryStatus(str, Enum):
    """Lifecycle states for a memory entry (FR-MI-01 write pipeline)."""
    QUARANTINED = "quarantined"   # Held for vetting — not yet readable
    ACTIVE = "active"             # Passed all checks — readable
    REJECTED = "rejected"         # Failed checks — never persisted/readable
    PURGED = "purged"             # Explicitly removed by admin


class MemoryRecord(BaseModel):
    """
    §12.3 — Long-term memory entry.

    Write path: status starts as QUARANTINED, promoted to ACTIVE or REJECTED
    by the Memory Integrity Layer pipeline.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    source_provenance: Provenance
    trust_label: TrustLabel = TrustLabel.UNTRUSTED_DATA
    integrity_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Composite integrity score (0=definitely bad, 1=fully trusted)",
    )
    status: MemoryStatus = MemoryStatus.QUARANTINED
    content_hash: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    quarantine_reason: str = ""             # Human-readable reason for quarantine/reject
    consistency_flags: list[str] = Field(
        default_factory=list,
        description="Flags from the consistency checker",
    )
    scan_score: float = 0.0                 # Raw injection scan score
    provenance_score: float = 0.0          # Score contribution from provenance trust

    @model_validator(mode="after")
    def compute_hash(self) -> "MemoryRecord":
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.content.encode("utf-8")
            ).hexdigest()
        return self

    @property
    def is_readable(self) -> bool:
        return self.status == MemoryStatus.ACTIVE

    @property
    def needs_review(self) -> bool:
        return self.status == MemoryStatus.QUARANTINED


class MemoryWriteRequest(BaseModel):
    """Request payload for POST /v1/mediate/memory/write."""
    session_id: str = ""
    content: str
    source: str = "agent"
    source_uri: str = ""
    trust_label: TrustLabel = TrustLabel.UNTRUSTED_DATA
    agent_id: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryReadRequest(BaseModel):
    """Request payload for POST /v1/mediate/memory/read."""
    session_id: str = ""
    memory_id: str
    agent_id: str = "default"
    rescan: bool = False                    # Force re-scan even if last_verified is recent
