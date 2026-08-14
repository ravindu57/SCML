"""
§6.5 — Memory Integrity Layer (PRIMARY CONTRIBUTION).

Vets every write to long-term memory before persistence and verifies every
read before re-entry into context (FR-MI-01 through FR-MI-05).

Write pipeline (5 stages):
  1. Quarantine  — candidate held; never readable
  2. Scan        — injection scanner evaluates content
  3. Consistency — checked against existing trusted facts
  4. Score       — composite integrity score computed
  5. Decision    — persist | quarantine | reject

Read verification:
  - Signature/provenance check
  - Conditional re-scan (policy-driven or forced)
  - Withhold if re-scan verdict would block

Admin operations:
  - list_quarantined()  — FR-MI-05
  - review_and_release() — human approval to promote quarantined entry
  - purge()              — hard delete a quarantined/rejected entry
"""

from __future__ import annotations

import structlog

from trust_mediator.config import settings
from trust_mediator.db.memory_repo import MemoryRepository
from trust_mediator.models.context_envelope import Provenance
from trust_mediator.models.memory_record import (
    MemoryRecord,
    MemoryReadRequest,
    MemoryStatus,
    MemoryWriteRequest,
)
from trust_mediator.modules.injection_scanner.scanner import InjectionScanner
from trust_mediator.modules.memory_integrity.consistency_checker import (
    ConsistencyChecker,
    ConsistencyReport,
)
from trust_mediator.modules.memory_integrity.scorer import (
    IntegrityScoreBreakdown,
    IntegrityScorer,
)

logger = structlog.get_logger(__name__)


class MemoryWriteResult:
    def __init__(
        self,
        record: MemoryRecord,
        verdict: str,
        score_breakdown: dict,
        blocked: bool = False,
    ) -> None:
        self.record = record
        self.verdict = verdict          # "persist" | "quarantine" | "reject"
        self.score_breakdown = score_breakdown
        self.blocked = blocked


class MemoryReadResult:
    def __init__(
        self,
        record: MemoryRecord | None,
        verified: bool,
        withheld: bool = False,
        reason: str = "",
    ) -> None:
        self.record = record
        self.verified = verified
        self.withheld = withheld
        self.reason = reason


class MemoryIntegrityLayer:
    """
    The central contribution of TrustMediator.

    Addresses OWASP ASI06 (Memory & Context Poisoning): a single injected
    memory record can steer many future sessions. This layer ensures nothing
    enters or exits long-term memory without passing an integrity gauntlet.
    """

    def __init__(
        self,
        repo: MemoryRepository | None = None,
        scanner: InjectionScanner | None = None,
        integrity_threshold: float | None = None,
        checker: ConsistencyChecker | None = None,
    ) -> None:
        self._repo = repo or MemoryRepository()
        self._scanner = scanner or InjectionScanner()
        threshold = integrity_threshold or settings.memory_integrity_threshold
        self._scorer = IntegrityScorer(
            persist_threshold=threshold,
            reject_threshold=threshold * 0.5,
        )
        # Injectable so the §14.3 ablation harness can disable stage 3 without
        # the production path branching on whether it is being benchmarked.
        self._checker = checker or ConsistencyChecker()

    # ── Write pipeline ────────────────────────────────────────────────────────

    async def vet_write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        """
        Run a candidate memory write through the full 5-stage vetting pipeline.

        Fail-closed (§9): on any pipeline error, the entry is quarantined
        rather than persisted, preventing silent poisoning during degraded ops.
        """
        # Build initial record in QUARANTINED state (stage 1)
        provenance = Provenance(
            source=request.source,
            uri=request.source_uri,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )
        record = MemoryRecord(
            content=request.content,
            source_provenance=provenance,
            trust_label=request.trust_label,
            status=MemoryStatus.QUARANTINED,
            metadata=request.metadata,
        )

        logger.info(
            "memory_integrity.write_started",
            record_id=record.id,
            trust_label=record.trust_label,
            session=request.session_id,
        )

        try:
            # Stages 2-4: scan → consistency → score
            record, breakdown, consistency_report = await self._evaluate(
                record, request.agent_id
            )

            # Stage 5: Decision
            verdict = breakdown.verdict
            if verdict == "persist":
                final_status = MemoryStatus.ACTIVE
                reason = ""
            elif verdict == "quarantine":
                final_status = MemoryStatus.QUARANTINED
                reason = f"Score {breakdown.composite:.2f} below persist threshold; flags: {consistency_report.flags}"
            else:  # reject
                final_status = MemoryStatus.REJECTED
                reason = f"Score {breakdown.composite:.2f} below reject threshold; high-risk content blocked"

            record = record.model_copy(
                update={
                    "status": final_status,
                    "quarantine_reason": reason,
                }
            )

            # Persist to store
            await self._repo.save(record, agent_id=request.agent_id)

            logger.info(
                "memory_integrity.write_complete",
                record_id=record.id,
                verdict=verdict,
                score=breakdown.composite,
                status=final_status,
            )

            return MemoryWriteResult(
                record=record,
                verdict=verdict,
                score_breakdown={
                    "composite": breakdown.composite,
                    "provenance": breakdown.provenance_score,
                    "scan": breakdown.scan_score,
                    "consistency": breakdown.consistency_score,
                },
                blocked=(final_status == MemoryStatus.REJECTED),
            )

        except Exception as e:
            # Fail-closed: quarantine on any error
            logger.error(
                "memory_integrity.write_pipeline_error",
                error=str(e),
                record_id=record.id,
            )
            record = record.model_copy(
                update={
                    "status": MemoryStatus.QUARANTINED,
                    "quarantine_reason": f"Pipeline error (fail-closed): {e}",
                }
            )
            await self._repo.save(record, agent_id=request.agent_id)
            return MemoryWriteResult(
                record=record,
                verdict="quarantine",
                score_breakdown={},
                blocked=False,
            )

    async def _evaluate(
        self, record: MemoryRecord, agent_id: str
    ) -> tuple[MemoryRecord, IntegrityScoreBreakdown, ConsistencyReport]:
        """
        Run stages 2-4 (scan → consistency → score) over a candidate record.

        Shared by the write and read paths so both apply an identical standard.
        They previously diverged: the read path only re-scanned, which meant a
        record that would have been quarantined at write time was served back
        to the agent unchallenged.
        """
        record, _ = await self._stage_scan(record)
        consistency_report = await self._stage_consistency(record, agent_id)
        breakdown = self._scorer.score(record, consistency_report)
        record = record.model_copy(
            update={
                "integrity_score": breakdown.composite,
                "scan_score": breakdown.scan_score,
                "provenance_score": breakdown.provenance_score,
                "consistency_flags": consistency_report.flags,
            }
        )
        return record, breakdown, consistency_report

    async def _stage_scan(self, record: MemoryRecord) -> tuple[MemoryRecord, float]:
        """Stage 2: run the injection scanner over candidate content."""
        from trust_mediator.models.context_envelope import ContextEnvelope
        envelope = ContextEnvelope(
            content=record.content,
            trust_label=record.trust_label,
            provenance=record.source_provenance,
        )
        # scan_async: _stage_scan is on an event loop (see scanner.scan_async).
        scanned = await self._scanner.scan_async(envelope)
        scan_score = scanned.scanner_verdict.score

        logger.debug(
            "memory_integrity.scan_stage",
            record_id=record.id,
            scan_decision=scanned.scanner_verdict.decision,
            scan_score=scan_score,
        )
        return record.model_copy(update={"scan_score": scan_score}), scan_score

    async def _stage_consistency(self, record: MemoryRecord, agent_id: str):
        """Stage 3: check consistency against existing active memory."""
        existing = await self._repo.list_active(agent_id=agent_id)
        # Exclude the record itself (shouldn't be there, but guard)
        existing = [r for r in existing if r.id != record.id]
        return self._checker.check(record.content, existing)

    # ── Read verification ─────────────────────────────────────────────────────

    async def verify_read(self, request: MemoryReadRequest) -> MemoryReadResult:
        """
        Verify a memory record before it re-enters the agent's context (FR-MI-04).

        Checks:
          1. Record exists and is ACTIVE
          2. Content hash matches (tamper-evidence)
          3. Optional: re-scan if policy requires or caller forces it
        """
        record = await self._repo.get(request.memory_id)
        if record is None:
            return MemoryReadResult(
                record=None,
                verified=False,
                withheld=True,
                reason="memory_not_found",
            )

        if not record.is_readable:
            return MemoryReadResult(
                record=record,
                verified=False,
                withheld=True,
                reason=f"memory_status_is_{record.status.value}",
            )

        # Hash integrity check
        import hashlib
        current_hash = hashlib.sha256(record.content.encode("utf-8")).hexdigest()
        if current_hash != record.content_hash:
            logger.error(
                "memory_integrity.hash_mismatch",
                record_id=record.id,
                expected=record.content_hash,
                actual=current_hash,
            )
            await self._repo.update_status(
                record.id,
                MemoryStatus.QUARANTINED,
                "Hash mismatch detected on read — possible tampering",
            )
            return MemoryReadResult(
                record=record,
                verified=False,
                withheld=True,
                reason="hash_mismatch_possible_tampering",
            )

        # Re-verification (policy-driven or forced).
        #
        # This applies the full write-path gauntlet, not a bare re-scan. The
        # two paths used to disagree: a record scoring below the persist
        # threshold was refused at write time but served at read time, because
        # the read check only withheld on a block/escalate scanner verdict.
        # Anything the scanner scored below its escalate threshold was handed
        # to the agent regardless of how the other signals rated it — which is
        # exactly the pre-existing-poison case FR-MI-04 exists to catch.
        should_rescan = request.rescan or settings.memory_rescan_on_read
        if should_rescan:
            rescored, breakdown, report = await self._evaluate(record, request.agent_id)
            if breakdown.verdict != "persist":
                logger.warning(
                    "memory_integrity.reverification_withheld",
                    record_id=record.id,
                    composite=breakdown.composite,
                    verdict=breakdown.verdict,
                    flags=report.flags[:5],
                )
                await self._repo.update_status(
                    record.id,
                    MemoryStatus.QUARANTINED,
                    f"Re-verification on read scored {breakdown.composite:.2f} "
                    f"({breakdown.verdict}); withheld",
                )
                return MemoryReadResult(
                    record=rescored,
                    verified=False,
                    withheld=True,
                    reason="reverification_below_threshold",
                )

        await self._repo.update_verified_at(record.id)
        return MemoryReadResult(record=record, verified=True)

    # ── Admin operations (FR-MI-05) ───────────────────────────────────────────

    async def list_quarantined(self, agent_id: str = "default") -> list[MemoryRecord]:
        """Return all quarantined entries for human review."""
        return await self._repo.list_quarantined(agent_id=agent_id)

    async def review_and_release(
        self, memory_id: str, reviewer: str = "human_reviewer"
    ) -> bool:
        """Promote a quarantined entry to ACTIVE after human review."""
        record = await self._repo.get(memory_id)
        if record is None or record.status != MemoryStatus.QUARANTINED:
            return False
        await self._repo.update_status(
            memory_id,
            MemoryStatus.ACTIVE,
            f"Released by reviewer: {reviewer}",
        )
        logger.info("memory_integrity.released", record_id=memory_id, reviewer=reviewer)
        return True

    async def purge(self, memory_id: str, reason: str = "admin_purge") -> bool:
        """Hard-delete (mark as PURGED) a quarantined or rejected entry."""
        await self._repo.update_status(memory_id, MemoryStatus.PURGED, reason)
        logger.info("memory_integrity.purged", record_id=memory_id, reason=reason)
        return True
