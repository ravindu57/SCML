"""
Audit event data model — §12.4 of the TrustMediator PRD.

The audit log is append-only and tamper-evident. Each event carries a
SHA-256 hash of the previous event, forming a verifiable hash chain
(FR-AL-01). Events are written asynchronously off the request path
(NFR-PERF-04).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuditModule(str, Enum):
    """Which pipeline module produced the event."""
    INGRESS = "ingress"
    TRUST_ROUTER = "trust_router"
    INJECTION_SCANNER = "injection_scanner"
    TOOL_POLICY = "tool_policy"
    MEMORY_INTEGRITY = "memory_integrity"
    OUTPUT_REDACTION = "output_redaction"
    PIPELINE = "pipeline"
    POLICY_STORE = "policy_store"
    SYSTEM = "system"


class AuditDecision(str, Enum):
    """High-level outcome recorded in each audit event."""
    ALLOW = "allow"
    BLOCK = "block"
    TRANSFORM = "transform"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    PERSIST = "persist"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    SHADOW = "shadow"
    ERROR = "error"


class AuditEvent(BaseModel):
    """
    §12.4 — A single immutable audit record.

    The hash chain is built by the AuditLogger, not here, so `prev_hash`
    and `seq_no` are populated at write time.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    seq_no: int = 0                          # Set by AuditLogger (monotonically increasing)
    session_id: str = ""
    module: AuditModule = AuditModule.SYSTEM
    decision: AuditDecision
    reason_code: str = ""
    input_provenance: dict[str, Any] = Field(
        default_factory=dict,
        description="Serialised provenance of the primary input",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific details (scan score, policy rule, etc.)",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    prev_hash: str = ""                      # SHA-256(prev_event), "" for first event
    event_hash: str = ""                     # SHA-256(this event without event_hash)
    agent_id: str = "default"
    context_id: str = ""                     # ID of the ContextEnvelope involved

    def compute_hash(self, prev_hash: str = "") -> str:
        """
        Compute SHA-256 hash for this event for tamper-evidence.
        Call after all other fields are set.
        """
        payload = {
            "id": self.id,
            "seq_no": self.seq_no,
            "session_id": self.session_id,
            "module": self.module,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "timestamp": self.timestamp.isoformat(),
            "prev_hash": prev_hash,
            "details": self.details,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def finalize(self, seq_no: int, prev_hash: str) -> "AuditEvent":
        """Return a new (frozen) event with seq_no and hash chain populated."""
        updated = self.model_copy(update={"seq_no": seq_no, "prev_hash": prev_hash})
        updated.event_hash = updated.compute_hash(prev_hash)
        return updated


class SessionReplay(BaseModel):
    """Response schema for GET /v1/audit/replay/{sessionId}."""
    session_id: str
    event_count: int
    events: list[AuditEvent]
    chain_valid: bool                       # True if hash chain verifies end-to-end
    integrity_issues: list[str] = Field(default_factory=list)
