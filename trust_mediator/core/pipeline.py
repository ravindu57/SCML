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

logger = structlog.get_logger(__name__)


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

    # ── §5.3 Step 1+2+3: Context mediation ───────────────────────────────────

    async def process_context(self, envelope: ContextEnvelope) -> ContextEnvelope:
        """
        Route, label, and scan a context envelope.
        Returns the envelope with scanner_verdict populated.
        Blocked items: scanner_verdict.decision = BLOCK.
        """
        # Step 2: trust routing
        routed = self._router.route(envelope)

        # Step 3: injection scan (trusted instructions skip scanning)
        scanned = self._scanner.scan(routed)

        # Audit
        decision = (
            AuditDecision.ALLOW
            if scanned.scanner_verdict.decision == ScanVerdict.ALLOW
            else AuditDecision(scanned.scanner_verdict.decision.value)
        )
        event = self._audit.make_event(
            session_id=envelope.session_id,
            module=AuditModule.INJECTION_SCANNER,
            decision=decision,
            reason_code=scanned.scanner_verdict.decision.value,
            details={
                "score": scanned.scanner_verdict.score,
                "patterns": scanned.scanner_verdict.patterns_matched[:5],
                "trust_label": scanned.trust_label.value,
            },
            input_provenance=envelope.provenance.model_dump(mode="json"),
            context_id=envelope.id,
        )
        self._audit.log(event)

        return scanned

    # ── §5.3 Step 4: Tool call policy ─────────────────────────────────────────

    async def process_tool_call(self, request: ToolCallRequest):
        """Evaluate a proposed tool call against policy. Returns PolicyDecision."""
        decision = await self._policy_engine.evaluate(request)
        request.policy_decision = decision

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
        self._audit.log(event)
        return decision

    # ── §5.3 Step 6: Memory ops ───────────────────────────────────────────────

    async def process_memory_write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        result = await self._memory.vet_write(request)
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
        self._audit.log(event)
        return result

    async def process_memory_read(self, request: MemoryReadRequest) -> MemoryReadResult:
        result = await self._memory.verify_read(request)
        audit_decision = AuditDecision.ALLOW if result.verified else AuditDecision.BLOCK
        event = self._audit.make_event(
            session_id=request.session_id,
            module=AuditModule.MEMORY_INTEGRITY,
            decision=audit_decision,
            reason_code="verified" if result.verified else result.reason,
            details={"memory_id": request.memory_id, "withheld": result.withheld},
            agent_id=request.agent_id,
        )
        self._audit.log(event)
        return result

    # ── §5.3 Step 7: Output redaction ─────────────────────────────────────────

    async def process_output(
        self,
        content: str,
        session_id: str = "",
        destination: str = "user",
        data_class_labels: list[str] | None = None,
    ) -> RedactionResult:
        result = self._redactor.redact(
            content, destination=destination, data_class_labels=data_class_labels
        )
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
        self._audit.log(event)
        return result

    # ── Audit replay ──────────────────────────────────────────────────────────

    async def replay_session(self, session_id: str):
        return await self._audit.replay(session_id)

    async def start(self) -> None:
        """Start background services (audit writer)."""
        await self._audit.start()

    async def stop(self) -> None:
        await self._audit.stop()
