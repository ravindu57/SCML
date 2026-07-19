"""
POST /v1/mediate/memory/* — memory integrity endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from trust_mediator.api.auth import AuthDep
from trust_mediator.api.dependencies import PipelineDep
from trust_mediator.models.context_envelope import TrustLabel
from trust_mediator.models.memory_record import MemoryReadRequest, MemoryStatus, MemoryWriteRequest

router = APIRouter(prefix="/v1/mediate/memory", tags=["memory"])


class MemoryWriteBody(BaseModel):
    session_id: str = ""
    content: str
    source: str = "agent"
    source_uri: str = ""
    trust_label: str = "untrusted_data"
    agent_id: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryWriteResponse(BaseModel):
    record_id: str
    verdict: str                  # "persist" | "quarantine" | "reject"
    status: str
    integrity_score: float
    score_breakdown: dict[str, float]
    blocked: bool
    quarantine_reason: str


class MemoryReadBody(BaseModel):
    session_id: str = ""
    memory_id: str
    agent_id: str = "default"
    rescan: bool = False


class MemoryReadResponse(BaseModel):
    memory_id: str
    verified: bool
    withheld: bool
    reason: str
    content: str | None = None
    integrity_score: float | None = None


class QuarantineListResponse(BaseModel):
    records: list[dict[str, Any]]


@router.post("/write", response_model=MemoryWriteResponse, summary="Vet a candidate memory write")
async def memory_write(body: MemoryWriteBody, pipeline: PipelineDep, _: AuthDep):
    """
    FR-MI-01: Run the full 5-stage memory write vetting pipeline.
    Returns persist | quarantine | reject with integrity score.
    """
    try:
        label = TrustLabel(body.trust_label)
    except ValueError:
        label = TrustLabel.UNTRUSTED_DATA

    request = MemoryWriteRequest(
        session_id=body.session_id,
        content=body.content,
        source=body.source,
        source_uri=body.source_uri,
        trust_label=label,
        agent_id=body.agent_id,
        metadata=body.metadata,
    )
    result = await pipeline.process_memory_write(request)
    return MemoryWriteResponse(
        record_id=result.record.id,
        verdict=result.verdict,
        status=result.record.status.value,
        integrity_score=result.record.integrity_score,
        score_breakdown=result.score_breakdown,
        blocked=result.blocked,
        quarantine_reason=result.record.quarantine_reason,
    )


@router.post("/read", response_model=MemoryReadResponse, summary="Verify a memory read")
async def memory_read(body: MemoryReadBody, pipeline: PipelineDep, _: AuthDep):
    """
    FR-MI-04: Verify provenance/integrity of a memory read before context re-entry.
    """
    request = MemoryReadRequest(
        session_id=body.session_id,
        memory_id=body.memory_id,
        agent_id=body.agent_id,
        rescan=body.rescan,
    )
    result = await pipeline.process_memory_read(request)
    return MemoryReadResponse(
        memory_id=body.memory_id,
        verified=result.verified,
        withheld=result.withheld,
        reason=result.reason,
        content=result.record.content if (result.record and result.verified) else None,
        integrity_score=result.record.integrity_score if result.record else None,
    )


@router.get("/quarantined", response_model=QuarantineListResponse, summary="List quarantined memory entries")
async def list_quarantined(agent_id: str = "default", pipeline: PipelineDep = None):
    """FR-MI-05: Return all quarantined entries for human review."""
    records = await pipeline._memory.list_quarantined(agent_id=agent_id)
    return QuarantineListResponse(
        records=[
            {
                "id": r.id,
                "content_preview": r.content[:200],
                "integrity_score": r.integrity_score,
                "quarantine_reason": r.quarantine_reason,
                "created_at": r.created_at.isoformat(),
                "trust_label": r.trust_label.value,
            }
            for r in records
        ]
    )


@router.post("/quarantined/{memory_id}/release", summary="Release a quarantined memory entry after review")
async def release_quarantined(memory_id: str, reviewer: str = "human_reviewer", pipeline: PipelineDep = None):
    """FR-MI-05: Promote a quarantined entry to ACTIVE after human review."""
    success = await pipeline._memory.review_and_release(memory_id, reviewer=reviewer)
    if not success:
        raise HTTPException(status_code=404, detail="Memory record not found or not in quarantined state")
    return {"released": True, "memory_id": memory_id}


@router.delete("/quarantined/{memory_id}", summary="Purge a quarantined or rejected memory entry")
async def purge_quarantined(memory_id: str, reason: str = "admin_purge", pipeline: PipelineDep = None):
    """FR-MI-05: Hard-delete a quarantined/rejected entry."""
    await pipeline._memory.purge(memory_id, reason=reason)
    return {"purged": True, "memory_id": memory_id}
