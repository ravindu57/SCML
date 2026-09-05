"""
Tool-call data model — §12.2 of the TrustMediator PRD.

Every proposed tool invocation is wrapped in a ToolCallRequest and
passed through the policy engine before execution.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from trust_mediator.models.context_envelope import TrustLabel


class PolicyDecisionCode(str, Enum):
    """Machine-readable reason codes for policy decisions (§10.2)."""
    ALLOW = "allow"
    DENY_NOT_ALLOWLISTED = "deny.not_allowlisted"
    DENY_SCHEMA_VIOLATION = "deny.schema_violation"
    DENY_VALUE_CONSTRAINT = "deny.value_constraint"
    DENY_RATE_LIMIT = "deny.rate_limit"
    DENY_UNTRUSTED_ARG = "deny.untrusted_arg"
    DENY_POLICY_NOT_LOADED = "deny.policy_not_loaded"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_APPROVAL_IRREVERSIBLE = "require_approval.irreversible"
    REQUIRE_APPROVAL_HIGH_IMPACT = "require_approval.high_impact"
    REQUIRE_APPROVAL_UNTRUSTED_ARG = "require_approval.untrusted_arg"
    MEDIATOR_ERROR = "mediator_error"


class PolicyDecision(BaseModel):
    """Outcome of the tool-call policy engine for a single call."""
    decision: PolicyDecisionCode = PolicyDecisionCode.DENY_POLICY_NOT_LOADED
    reason: str = ""
    reason_code: PolicyDecisionCode = PolicyDecisionCode.DENY_POLICY_NOT_LOADED
    approver_required: bool = False
    approval_id: str | None = None          # Set when require_approval is issued
    audit_ref: str = ""                     # Reference into the audit log

    @property
    def is_allowed(self) -> bool:
        return self.decision == PolicyDecisionCode.ALLOW

    @property
    def requires_approval(self) -> bool:
        return self.decision == PolicyDecisionCode.REQUIRE_APPROVAL or str(
            self.decision
        ).startswith("require_approval")


class ToolCallRequest(BaseModel):
    """
    §12.2 — Canonical representation of a proposed tool invocation.

    Submitted to `POST /v1/mediate/tool-call` for authorisation before
    the tool is actually called.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    argument_trust_labels: dict[str, TrustLabel] = Field(
        default_factory=dict,
        description="Per-argument trust labels (set by trust router from arg provenance)",
    )
    invoking_context_id: str = ""           # ID of the ContextEnvelope that triggered this
    agent_id: str = "default"
    #: The policy tenant this request is evaluated under. Set **server-side**
    #: from the authenticated API key (see ``CallerDep``); the HTTP request
    #: model deliberately does not accept it, so a caller cannot choose another
    #: tenant. Object-API callers constructing this model directly set it to
    #: whatever namespaced policy document they want to evaluate against.
    tenant_id: str = "default"
    is_irreversible: bool = False           # Caller hint; policy may override
    is_high_impact: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_decision: PolicyDecision | None = None   # Populated after engine evaluation

    @property
    def has_untrusted_args(self) -> bool:
        """True if any argument derives from untrusted/risky content."""
        untrusted = {TrustLabel.UNTRUSTED_DATA, TrustLabel.RISKY_EXTERNAL}
        return any(lbl in untrusted for lbl in self.argument_trust_labels.values())
