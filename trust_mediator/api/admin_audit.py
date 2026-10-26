"""
Audit records for control-plane actions (FR-AL-01, FR-CP-03; Sec #9).

Policy writes, rollbacks, and quarantine release and purge changed what the
mediator enforces, or what an agent may read, and left nothing in the hash
chain. They now append to a per-tenant control-plane chain
(``core.tenancy.control_session``), which no client session id can reach and
only that tenant's admins can replay (``GET /v1/audit/control-plane``).

Refused attempts are recorded too (``decision=reject``), and a store failure
mid-action as ``decision=error``: an admin key trying
an invalid policy, or a release of a record that is not there, is exactly
what an investigator wants to see. Requests refused at authentication never
reach these handlers and are not recorded here.

Recording never fails the request: the action has already happened, and an
audit outage must not turn into a control-plane outage. ``AuditLogger.log``
is non-blocking and accounts for its own drops.
"""
from __future__ import annotations

from typing import Any

import structlog

from trust_mediator.api.auth import Caller
from trust_mediator.core.tenancy import control_session
from trust_mediator.models.audit_event import AuditDecision, AuditModule

logger = structlog.get_logger(__name__)


def record_admin_action(
    audit,
    admin: Caller,
    action: str,
    *,
    module: AuditModule,
    succeeded: bool,
    details: dict[str, Any] | None = None,
    errored: bool = False,
) -> None:
    """``errored`` marks a store failure (the action may or may not have
    committed) as opposed to a refusal; it is recorded as ``error``."""
    try:
        audit.log(
            audit.make_event(
                session_id=control_session(admin.tenant),
                module=module,
                decision=(
                    AuditDecision.ERROR if errored
                    else AuditDecision.ALLOW if succeeded
                    else AuditDecision.REJECT
                ),
                reason_code=action,
                details={"principal": admin.principal, "tenant": admin.tenant, **(details or {})},
                agent_id=admin.principal,
            )
        )
    except Exception as e:  # pragma: no cover - log() does not raise today
        logger.error("admin_audit.record_failed", action=action, error=str(e))
