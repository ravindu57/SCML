"""
GET /v1/audit/* — audit replay and forensics endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from trust_mediator.api.auth import AdminDep, CallerDep, session_for
from trust_mediator.core.tenancy import control_session
from trust_mediator.api.dependencies import PipelineDep
from trust_mediator.models.audit_event import SessionReplay

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("/replay/{session_id}", response_model=SessionReplay, summary="Replay full decision trail for a session")
async def replay_session(session_id: str, pipeline: PipelineDep, caller: CallerDep):
    """
    FR-AL-02: Return the ordered, verifiable event trail for a session.
    Includes chain_valid flag indicating whether the hash chain verifies end-to-end.

    Scoped to the caller's tenant: the same session id from another company's
    key is a different (usually empty) chain.
    """
    replay = await pipeline.replay_session(session_for(caller, session_id))
    return replay


@router.get("/control-plane", response_model=SessionReplay, summary="Replay the tenant's admin actions")
async def replay_control_plane(pipeline: PipelineDep, admin: AdminDep):
    """FR-AL-02 for the control plane: policy changes, rollbacks, quarantine
    release and purge in the admin key's tenant, as a verifiable chain.

    Admin-only. The chain is not reachable through ``/replay/{session_id}``.
    """
    return await pipeline.replay_session(control_session(admin.tenant))
