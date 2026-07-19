"""
gRPC server for the mediation pipeline (FR-IG-02).

Exposes the same five mediation operations as the REST API, backed by the
same MediationPipeline instance, so both transports enforce identical
policy and produce identical audit trails.

Enable with TRUST_MEDIATOR_GRPC_ENABLED=true (port TRUST_MEDIATOR_GRPC_PORT,
default 50051). Authentication mirrors REST: when API keys are configured,
callers must send an `x-api-key` metadata entry.
"""

from __future__ import annotations

import json

import grpc
import structlog

from trust_mediator.config import settings
from trust_mediator.api.grpc import mediation_pb2, mediation_pb2_grpc
from trust_mediator.core.pipeline import MediationPipeline
from trust_mediator.models.context_envelope import ContextEnvelope, Provenance
from trust_mediator.models.memory_record import MemoryReadRequest, MemoryWriteRequest
from trust_mediator.models.tool_call import ToolCallRequest

logger = structlog.get_logger(__name__)


class _ApiKeyInterceptor(grpc.aio.ServerInterceptor):
    """Reject unauthenticated calls when API keys are configured (parity
    with the REST auth dependency)."""

    def __init__(self) -> None:
        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid or missing x-api-key")

        self._abort_handler = grpc.unary_unary_rpc_method_handler(abort)

    async def intercept_service(self, continuation, handler_call_details):
        keys = settings.api_keys
        if not keys:  # open access (development)
            return await continuation(handler_call_details)
        metadata = dict(handler_call_details.invocation_metadata or ())
        if metadata.get("x-api-key") in keys:
            return await continuation(handler_call_details)
        return self._abort_handler


class MediationServicer(mediation_pb2_grpc.MediationServiceServicer):
    def __init__(self, pipeline: MediationPipeline) -> None:
        self._pipeline = pipeline

    async def MediateContext(self, request, context):
        envelope = ContextEnvelope(
            session_id=request.session_id,
            content=request.content,
            provenance=Provenance(
                source=request.source or "tool_result",
                uri=request.source_uri,
            ),
        )
        scanned = await self._pipeline.process_context(envelope)
        verdict = scanned.scanner_verdict
        return mediation_pb2.ContextResponse(
            context_id=scanned.id,
            trust_label=scanned.trust_label.value,
            decision=verdict.decision.value,
            score=verdict.score,
            rationale=verdict.rationale,
            # In transform mode the scanner replaces content with a sanitised
            # summary; this mirrors the REST response's `content` field.
            sanitised_content=scanned.content,
        )

    async def MediateToolCall(self, request, context):
        try:
            arguments = json.loads(request.arguments_json) if request.arguments_json else {}
        except json.JSONDecodeError:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "arguments_json is not valid JSON"
            )
        tool_request = ToolCallRequest(
            session_id=request.session_id,
            agent_id=request.agent_id or "default",
            tool_name=request.tool_name,
            arguments=arguments,
            argument_trust_labels=dict(request.argument_trust_labels),
            is_irreversible=request.is_irreversible,
            is_high_impact=request.is_high_impact,
        )
        decision = await self._pipeline.process_tool_call(tool_request)
        return mediation_pb2.ToolCallResponse(
            decision=(
                "allow" if decision.is_allowed
                else "require_approval" if decision.requires_approval
                else "deny"
            ),
            reason=decision.reason,
            reason_code=decision.reason_code.value,
            approver_required=decision.approver_required,
            approval_id=decision.approval_id or "",
        )

    async def MediateMemoryWrite(self, request, context):
        result = await self._pipeline.process_memory_write(
            MemoryWriteRequest(
                session_id=request.session_id,
                agent_id=request.agent_id or "default",
                content=request.content,
                source=request.source or "agent_output",
                trust_label=request.trust_label or "untrusted_data",
            )
        )
        return mediation_pb2.MemoryWriteResponse(
            verdict=result.verdict,
            record_id=result.record.id,
            integrity_score=result.record.integrity_score,
            reason=result.record.quarantine_reason,
        )

    async def MediateMemoryRead(self, request, context):
        result = await self._pipeline.process_memory_read(
            MemoryReadRequest(
                session_id=request.session_id,
                agent_id=request.agent_id or "default",
                memory_id=request.memory_id,
                rescan=request.rescan,
            )
        )
        return mediation_pb2.MemoryReadResponse(
            verified=result.verified,
            withheld=result.withheld,
            reason=result.reason or "",
            content=(result.record.content if result.verified and result.record else ""),
        )

    async def MediateOutput(self, request, context):
        result = await self._pipeline.process_output(
            request.content,
            session_id=request.session_id,
            destination=request.destination or "user",
            data_class_labels=list(request.data_class_labels),
        )
        return mediation_pb2.OutputResponse(
            blocked=result.blocked,
            block_reason=result.block_reason or "",
            redacted_content=result.content,
            redactions_count=len(result.redactions_applied),
        )

    async def Health(self, request, context):
        return mediation_pb2.HealthResponse(status="ok", version="1.0.0")


async def create_grpc_server(
    pipeline: MediationPipeline, port: int | None = None
) -> grpc.aio.Server:
    """Build (but do not start) the gRPC server bound to the shared pipeline."""
    server = grpc.aio.server(interceptors=[_ApiKeyInterceptor()])
    mediation_pb2_grpc.add_MediationServiceServicer_to_server(
        MediationServicer(pipeline), server
    )
    bind = f"{settings.host}:{port or settings.grpc_port}"
    server.add_insecure_port(bind)  # TLS terminates at the mesh/ingress (NFR-SEC-03)
    logger.info("grpc.server_configured", bind=bind)
    return server
