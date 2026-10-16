"""
GET /v1/audit/* — audit replay and forensics endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from trust_mediator.api.auth import CallerDep, session_for
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
