"""
GET /v1/audit/* — audit replay and forensics endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from trust_mediator.api.auth import AuthDep
from trust_mediator.api.dependencies import PipelineDep
from trust_mediator.models.audit_event import SessionReplay

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("/replay/{session_id}", response_model=SessionReplay, summary="Replay full decision trail for a session")
async def replay_session(session_id: str, pipeline: PipelineDep, _: AuthDep):
    """
    FR-AL-02: Return the ordered, verifiable event trail for a session.
    Includes chain_valid flag indicating whether the hash chain verifies end-to-end.
    """
    replay = await pipeline.replay_session(session_id)
    return replay
