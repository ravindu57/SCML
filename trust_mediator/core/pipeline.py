"""
Core mediation pipeline — wires all 8 modules together.

The MediationPipeline is the single object that the API layer and SDK
adapters use. It orchestrates the full request lifecycle from §5.3.
"""

from __future__ import annotations

from typing import Any

import structlog

from trust_mediator.config import settings
from trust_mediator.db.memory_repo import MemoryRepository
from trust_mediator.db.policy_repo import PolicyRepository
from trust_mediator.models.audit_event import AuditDecision, AuditModule
from trust_mediator.models.context_envelope import ContextEnvelope, ScanVerdict
from trust_mediator.models.memory_record import MemoryReadRequest, MemoryWriteRequest
from trust_mediator.models.tool_call import ToolCallRequest
from trust_mediator.modules.audit_log.logger import AuditLogger
from trust_mediator.modules.injection_scanner.scanner import InjectionScanner
from trust_mediator.modules.memory_integrity.layer import MemoryIntegrityLayer, MemoryReadResult, MemoryWriteResult
from trust_mediator.modules.output_redaction.redactor import OutputRedactor, RedactionResult
from trust_mediator.modules.tool_policy.engine import PolicyEngine
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader
from trust_mediator.modules.trust_router.router import TrustRouter
from trust_mediator.observability import get_tracer, set_decision_attributes

logger = structlog.get_logger(__name__)

# NFR-OBS-01: one span per mediation decision point. No-op unless tracing is
# configured. Attributes carry decisions and labels only — never content.
tracer = get_tracer(__name__)


class MediationPipeline:
    """
    Orchestrates the full TrustMediator mediation pipeline.

    Lifecycle per request (§5.3):
      1. Ingress wrap (done by IngressInterceptor before calling pipeline)
      2. Trust routing
      3. Injection scanning
      4. Tool-call policy (for tool calls)
      5. Memory integrity (for memory ops)
      6. Output redaction (for egress)
      7. Audit logging (every step, async)
    """

    def __init__(
        self,
        policy_repo: PolicyRepository | None = None,
        memory_repo: MemoryRepository | None = None,
        audit_logger: AuditLogger | None = None,
        scanner: InjectionScanner | None = None,
        redaction_config: dict[str, Any] | None = None,
    ) -> None:
        self._router = TrustRouter()
        self._scanner = scanner or InjectionScanner()
        self._audit = audit_logger or AuditLogger()

        _policy_repo = policy_repo or PolicyRepository()
        self._loader = PolicyLoader(policy_repo=_policy_repo)
        self._policy_engine = PolicyEngine(self._loader)

        _mem_repo = memory_repo or MemoryRepository()
        self._memory = MemoryIntegrityLayer(
            repo=_mem_repo,
            scanner=self._scanner,
            integrity_threshold=settings.memory_integrity_threshold,
        )

        self._redactor = OutputRedactor(redaction_config)

    def _emit(self, event) -> None:
        """
        Hand an audit event to the logger without letting it break mediation.

        `AuditLogger.log()` is non-blocking and swallows its own overflow, but
        the pipeline must not depend on that: a mediator that refuses to make
        decisions because its logger is unhappy is an availability incident of
        its own making (§8.3). The audit path is critical, not load-bearing for
        the request — a dropped event is already accounted for by the queue's
        gap markers.
        """
        try:
            self._audit.log(event)
        except Exception as e:
            logger.error(
                "pipeline.audit_emit_failed",
                error=str(e),
                module=getattr(event, "module", None),
            )

    # ── §5.3 Step 1+2+3: Context mediation ───────────────────────────────────

    async def process_context(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """
        Route, label, and scan a context envelope.
        Returns the envelope with scanner_verdict populated.
        Blocked items: scanner_verdict.decision = BLOCK.
        """
        with tracer.start_as_current_span("mediate.context") as span:
            # Step 2: trust routing
            routed = self._router.route(envelope)

            # Step 3: injection scan (trusted instructions skip scanning).
            # scan_async, not scan: an I/O-backed classifier would otherwise
            # block this event loop for the whole round trip.
            scanned = await self._scanner.scan_async(routed)

            set_decision_attributes(
                span,
                module="injection_scanner",
                decision=scanned.scanner_verdict.decision.value,
                reason_code=scanned.scanner_verdict.decision.value,
                session_id=envelope.session_id,
                trust_label=scanned.trust_label.value,
                score=scanned.scanner_verdict.score,
            )

        # Audit. §9 requires every fail-open to be recorded explicitly, so an
        # operator can see exactly what proceeded unverified and why — an
        # unscannable item logged as a plain ALLOW would be invisible.
        unverified = not scanned.is_verified and bool(scanned.unverified_reason)
        if unverified and scanned.scanner_verdict.decision == ScanVerdict.ALLOW:
            # Genuinely failed open: unscannable, and it proceeded anyway.
            decision = AuditDecision.FAIL_OPEN
        elif scanned.scanner_verdict.decision == ScanVerdict.ALLOW:
            decision = AuditDecision.ALLOW
        else:
            # Unscannable but escalated or blocked — nothing opened, so record
            # the verdict that actually applied. Logging this as fail_open
            # would tell an operator content proceeded when it did not.
            decision = AuditDecision(scanned.scanner_verdict.decision.value)
        event = self._audit.make_event(
            session_id=envelope.session_id,
            module=AuditModule.INJECTION_SCANNER,
            decision=decision,
            reason_code=(
                scanned.unverified_reason
                if unverified
                else scanned.scanner_verdict.decision.value
            ),
            details={
                "score": scanned.scanner_verdict.score,
                "patterns": scanned.scanner_verdict.patterns_matched[:5],
                "trust_label": scanned.trust_label.value,
                "verified": scanned.is_verified,
            },
            input_provenance=envelope.provenance.model_dump(mode="json"),
            context_id=envelope.id,
        )
        self._emit(event)

        return scanned

    # ── §5.3 Step 4: Tool call policy ─────────────────────────────────────────

    async def process_tool_call(self, request: ToolCallRequest):
        """Evaluate a proposed tool call against policy. Returns PolicyDecision."""
        with tracer.start_as_current_span("mediate.tool_call") as span:
            decision = await self._policy_engine.evaluate(request)
            request.policy_decision = decision
            set_decision_attributes(
                span,
                module="tool_policy",
                decision=decision.reason_code.value,
                reason_code=decision.reason_code.value,
                session_id=request.session_id,
                agent_id=request.agent_id,
            )
            span.set_attribute("trustmediator.tool_name", request.tool_name)

        audit_decision = (
            AuditDecision.ALLOW if decision.is_allowed
            else AuditDecision.REQUIRE_APPROVAL if decision.requires_approval
            else AuditDecision.BLOCK
        )
        event = self._audit.make_event(
            session_id=request.session_id,
            module=AuditModule.TOOL_POLICY,
            decision=audit_decision,
            reason_code=decision.reason_code.value,
            details={"tool": request.tool_name, "reason": decision.reason},
            agent_id=request.agent_id,
        )
        self._emit(event)
        return decision

    # ── §5.3 Step 6: Memory ops ───────────────────────────────────────────────

    async def process_memory_write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        with tracer.start_as_current_span("mediate.memory_write") as span:
            result = await self._memory.vet_write(request)
            set_decision_attributes(
                span,
                module="memory_integrity",
                decision=result.verdict,
                reason_code=result.verdict,
                session_id=request.session_id,
                agent_id=request.agent_id,
                trust_label=request.trust_label.value,
                score=result.record.integrity_score,
            )

        audit_decision = {
            "persist": AuditDecision.PERSIST,
            "quarantine": AuditDecision.QUARANTINE,
            "reject": AuditDecision.REJECT,
        }.get(result.verdict, AuditDecision.QUARANTINE)

        event = self._audit.make_event(
            session_id=request.session_id,
            module=AuditModule.MEMORY_INTEGRITY,
            decision=audit_decision,
            reason_code=result.verdict,
            details={
                "record_id": result.record.id,
                "scores": result.score_breakdown,
                "status": result.record.status.value,
            },
            agent_id=request.agent_id,
        )
        self._emit(event)
        return result

    async def process_memory_read(self, request: MemoryReadRequest) -> MemoryReadResult:
        with tracer.start_as_current_span("mediate.memory_read") as span:
            result = await self._memory.verify_read(request)
            set_decision_attributes(
                span,
                module="memory_integrity",
                decision="verified" if result.verified else "withheld",
                reason_code=result.reason,
                session_id=request.session_id,
                agent_id=request.agent_id,
            )

        audit_decision = AuditDecision.ALLOW if result.verified else AuditDecision.BLOCK
        event = self._audit.make_event(
            session_id=request.session_id,
            module=AuditModule.MEMORY_INTEGRITY,
            decision=audit_decision,
            reason_code="verified" if result.verified else result.reason,
            details={"memory_id": request.memory_id, "withheld": result.withheld},
            agent_id=request.agent_id,
        )
        self._emit(event)
        return result

    # ── §5.3 Step 7: Output redaction ─────────────────────────────────────────

    async def process_output(
        self,
        content: str,
        session_id: str = "",
        destination: str = "user",
        data_class_labels: list[str] | None = None,
    ) -> RedactionResult:
        with tracer.start_as_current_span("mediate.output") as span:
            try:
                result = self._redactor.redact(
                    content, destination=destination, data_class_labels=data_class_labels
                )
            except Exception as e:
                # §9: fail CLOSED on redaction failure. Letting the exception
                # propagate would also avoid leaking, but it produces a 500
                # with no decision and no audit record — the operator learns
                # nothing about what was withheld or why.
                logger.error(
                    "pipeline.redaction_failed",
                    error=str(e),
                    destination=destination,
                    session_id=session_id,
                )
                result = RedactionResult(
                    content="",
                    blocked=True,
                    block_reason=f"Redaction failed — fail-closed: {type(e).__name__}",
                    action_allowed=False,
                )
            set_decision_attributes(
                span,
                module="output_redaction",
                decision="blocked" if result.blocked else "allowed",
                reason_code=result.block_reason or "",
                session_id=session_id,
            )
            span.set_attribute(
                "trustmediator.redactions_count", len(result.redactions_applied)
            )
            span.set_attribute("trustmediator.destination", destination)

        audit_decision = AuditDecision.BLOCK if result.blocked else AuditDecision.ALLOW
        event = self._audit.make_event(
            session_id=session_id,
            module=AuditModule.OUTPUT_REDACTION,
            decision=audit_decision,
            reason_code="blocked" if result.blocked else "allowed",
            details={
                "redactions_count": len(result.redactions_applied),
                "destination": destination,
                "block_reason": result.block_reason,
            },
        )
        self._emit(event)
        return result

    # ── Audit replay ──────────────────────────────────────────────────────────

    async def replay_session(self, session_id: str):
        return await self._audit.replay(session_id)

    async def start(self) -> None:
        """Start background services (audit writer)."""
        await self._audit.start()

    async def stop(self) -> None:
        await self._audit.stop()
