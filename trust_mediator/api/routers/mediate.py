"""
POST /v1/mediate/* — core mediation endpoints.

All mediation decisions flow through the MediationPipeline singleton.
Every response includes decision, reason_code, trust labels, and an audit_ref.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from trust_mediator.api.auth import AuthDep
from trust_mediator.api.dependencies import PipelineDep
from trust_mediator.api.rate_limit import limiter
from trust_mediator.models.context_envelope import Provenance, TrustLabel
from trust_mediator.models.memory_record import MemoryReadRequest, MemoryWriteRequest
from trust_mediator.models.tool_call import ToolCallRequest
from trust_mediator.modules.escalation.webhook import schedule_escalation_webhook
from trust_mediator.modules.ingress.interceptor import IngressInterceptor

router = APIRouter(prefix="/v1/mediate", tags=["mediation"])


# ── Request / response schemas ────────────────────────────────────────────────

class ContextMediationRequest(BaseModel):
    session_id: str = ""
    content: str
    source: str = "tool_result"          # "tool_result" | "rag_retrieval" | "web_content" | "memory"
    source_uri: str = ""
    agent_id: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextMediationResponse(BaseModel):
    envelope_id: str
    decision: str                         # "allow" | "block" | "transform" | "escalate"
    trust_label: str
    score: float
    rationale: str
    patterns_matched: list[str]
    content: str                          # Possibly sanitised content
    audit_ref: str = ""


class ToolCallMediationRequest(BaseModel):
    session_id: str = ""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    argument_trust_labels: dict[str, str] = Field(default_factory=dict)
    agent_id: str = "default"
    is_irreversible: bool = False
    is_high_impact: bool = False


class ToolCallMediationResponse(BaseModel):
    decision: str
    reason: str
    reason_code: str
    approver_required: bool
    approval_id: str | None = None
    audit_ref: str = ""


class OutputMediationRequest(BaseModel):
    session_id: str = ""
    content: str
    destination: str = "user"
    data_class_labels: list[str] = Field(default_factory=list)


class OutputMediationResponse(BaseModel):
    content: str
    blocked: bool
    block_reason: str
    redactions_applied: list[dict[str, str]]
    action_allowed: bool
    audit_ref: str = ""


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/context", response_model=ContextMediationResponse, summary="Label + scan retrieved/tool content")
async def mediate_context(request: Request, body: ContextMediationRequest, pipeline: PipelineDep, _: AuthDep):
    """
    FR-IG-01, FR-SC-01: Intercept and scan untrusted/risky content.
    Returns the verdict, trust label, and sanitised content.
    """
    interceptor = IngressInterceptor(session_id=body.session_id, agent_id=body.agent_id)

    # Wrap content in the appropriate envelope based on source
    source_map = {
        "tool_result": interceptor.wrap_tool_result,
        "rag_retrieval": lambda c, **kw: interceptor.wrap_retrieval(c, source_uri=body.source_uri or "unknown", **kw),
        "web_content": lambda c, **kw: interceptor.wrap_web_content(c, url=body.source_uri or "unknown"),
        "memory": lambda c, **kw: interceptor.wrap_memory_read(c, memory_id=body.source_uri or "unknown"),
    }
    wrap_fn = source_map.get(body.source, source_map["tool_result"])

    if body.source == "tool_result":
        envelope = wrap_fn(body.content, tool_name=body.source_uri or "unknown_tool")
    else:
        envelope = wrap_fn(body.content)

    scanned = await pipeline.process_context(envelope)

    # ── Human-in-the-Loop: fire escalation webhook for escalate decisions ────────
    if scanned.scanner_verdict.decision.value == "escalate":
        schedule_escalation_webhook(
            session_id=body.session_id,
            agent_id=body.agent_id,
            score=scanned.scanner_verdict.score,
            patterns_matched=scanned.scanner_verdict.patterns_matched,
            content_preview=body.content,
        )

    return ContextMediationResponse(
        envelope_id=scanned.id,
        decision=scanned.scanner_verdict.decision.value,
        trust_label=scanned.trust_label.value,
        score=scanned.scanner_verdict.score,
        rationale=scanned.scanner_verdict.rationale,
        patterns_matched=scanned.scanner_verdict.patterns_matched,
        content=scanned.content,
    )


@router.post("/tool-call", response_model=ToolCallMediationResponse, summary="Authorise a proposed tool call")
async def mediate_tool_call(request: ToolCallMediationRequest, pipeline: PipelineDep, _: AuthDep):
    """
    FR-PE-01: Authorise a tool call against least-agency policy before execution.
    """
    arg_labels = {
        k: TrustLabel(v) for k, v in request.argument_trust_labels.items()
        if v in TrustLabel.__members__.values()
    }
    tool_request = ToolCallRequest(
        session_id=request.session_id,
        tool_name=request.tool_name,
        arguments=request.arguments,
        argument_trust_labels=arg_labels,
        agent_id=request.agent_id,
        is_irreversible=request.is_irreversible,
        is_high_impact=request.is_high_impact,
    )
    decision = await pipeline.process_tool_call(tool_request)

    return ToolCallMediationResponse(
        decision=decision.decision.value,
        reason=decision.reason,
        reason_code=decision.reason_code.value,
        approver_required=decision.approver_required,
        approval_id=decision.approval_id,
    )


@router.post("/output", response_model=OutputMediationResponse, summary="Redact and authorise outbound response/action")
async def mediate_output(request: OutputMediationRequest, pipeline: PipelineDep, _: AuthDep):
    """
    FR-OR-01, FR-OR-02: Redact PII/secrets and block exfiltration.
    """
    result = await pipeline.process_output(
        content=request.content,
        session_id=request.session_id,
        destination=request.destination,
        data_class_labels=request.data_class_labels,
    )
    return OutputMediationResponse(
        content=result.content,
        blocked=result.blocked,
        block_reason=result.block_reason,
        redactions_applied=result.redactions_applied,
        action_allowed=result.action_allowed,
    )
