"""
§6.7 — Audit & Provenance Log.

Append-only, tamper-evident log of every mediation decision (FR-AL-01).
Written asynchronously off the request path (NFR-PERF-04).
Supports session replay (FR-AL-02) and SIEM forwarding (FR-AL-03).

Hash chain: each event records SHA-256(prev_event_hash + this_event_payload)
so any modification of a past event invalidates all subsequent hashes.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import structlog

from trust_mediator.config import settings
from trust_mediator.db.audit_repo import AuditRepository
from trust_mediator.models.audit_event import AuditDecision, AuditEvent, AuditModule, SessionReplay
from trust_mediator.modules.audit_log.kafka_forwarder import KafkaAuditForwarder

logger = structlog.get_logger(__name__)


class AuditLogger:
    """
    Async audit event writer with hash-chain tamper-evidence.

    Events are queued immediately (non-blocking) and written in a background
    task to keep audit logging off the request path (NFR-PERF-04).
    """

    def __init__(self, repo: AuditRepository | None = None) -> None:
        self._repo = repo or AuditRepository()
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(
            maxsize=max(0, settings.audit_queue_maxsize)
        )
        self._siem_url = settings.audit_siem_webhook_url
        self._kafka = KafkaAuditForwarder(settings.audit_kafka_bootstrap)
        self._worker_task: asyncio.Task | None = None
        self._batch_max = max(1, settings.audit_batch_max)
        self._overflow_policy = settings.audit_overflow_policy
        # Events dropped since the last gap marker, per session. Keyed by
        # session so a forensic replay of that session shows its own gap.
        self._dropped: dict[str, int] = {}
        #: Cumulative drops for the lifetime of this logger (metrics/tests).
        self.dropped_total = 0

    async def start(self) -> None:
        """Start the background writer task and optional Kafka forwarder."""
        self._worker_task = asyncio.create_task(self._writer_loop())
        await self._kafka.start()
        logger.info("audit_logger.started", kafka=self._kafka.active)

    async def stop(self) -> None:
        """Drain the queue and shut down the background writer."""
        if self._worker_task:
            await self._queue.join()
            self._worker_task.cancel()
        await self._kafka.stop()

    def log(self, event: AuditEvent) -> None:
        """
        Non-blocking: enqueue an event for background writing.
        Returns immediately — zero latency on the request path (NFR-PERF-04).

        Never blocks the caller even when the queue is full: back-pressure onto
        the request path would trade an audit problem for an availability one.
        Overflow is dropped per the configured policy and recorded, so the loss
        is visible rather than silent.
        """
        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass

        if self._overflow_policy == "drop_oldest":
            try:
                self._queue.get_nowait()
                # Keep join() accounting balanced — every get() needs one
                # task_done(), or stop() would hang waiting on a phantom item.
                self._queue.task_done()
                self._queue.put_nowait(event)
                self._record_drop(event.session_id, reason="evicted_oldest")
                return
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass  # raced with the writer; fall through to drop-newest

        self._record_drop(event.session_id, reason="queue_full")

    def _record_drop(self, session_id: str, *, reason: str) -> None:
        """
        Account for a dropped event.

        FR-AL-01 wants every decision recorded. Once the queue is saturated
        that is no longer possible, so the next best thing is to record
        precisely how much was lost and where — a known gap is recoverable
        forensics, an unknown one is not.
        """
        self._dropped[session_id] = self._dropped.get(session_id, 0) + 1
        self.dropped_total += 1
        # One line per drop would itself become a flood under overload; the
        # gap marker written into the chain carries the exact count.
        if self.dropped_total == 1 or self.dropped_total % 1000 == 0:
            logger.error(
                "audit_logger.events_dropped",
                reason=reason,
                dropped_total=self.dropped_total,
                queue_maxsize=self._queue.maxsize,
                hint="writer cannot keep up; raise AUDIT_QUEUE_MAXSIZE or scale the audit store",
            )

    async def log_async(self, event: AuditEvent) -> None:
        """
        Async enqueue. Unlike `log()` this awaits space, applying back-pressure
        to the caller rather than dropping — use it only off the request path,
        where waiting is preferable to losing the event.
        """
        await self._queue.put(event)

    async def _writer_loop(self) -> None:
        """
        Background coroutine: dequeue and persist events in batches.

        Writing one event per transaction capped audit throughput at ~140
        events/s, below what the request path sustains — so under load the
        queue grew without bound and decisions were lost on shutdown, an
        FR-AL-01 failure rather than a latency one (benchmarks/results/load.md).

        Batching is opportunistic: block for the first event, then take
        whatever else is already queued up to `audit_batch_max`. Under light
        load batches are size 1 and behaviour is unchanged; under heavy load
        they grow and amortise the transaction cost exactly when that matters.
        """
        while True:
            try:
                batch = [await self._queue.get()]
                while len(batch) < self._batch_max:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                try:
                    await self._write_batch(batch)
                    await self._flush_gap_markers()
                finally:
                    # One task_done per successful get(), whatever the outcome,
                    # or stop() would wait on join() forever.
                    for _ in batch:
                        self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("audit_logger.write_error", error=str(e))

    async def _flush_gap_markers(self) -> None:
        """
        Write one marker per session that lost events, then reset the counters.

        Written straight to the repository rather than through the queue: the
        queue is by definition full when drops happen, so enqueueing the record
        of a drop is the one thing guaranteed to fail. Because the marker joins
        the session's own hash chain, `replay(session_id)` shows the gap in
        position — the chain stays verifiable and the hole is explicit.
        """
        if not self._dropped:
            return
        pending, self._dropped = self._dropped, {}
        for session_id, count in pending.items():
            marker = self.make_event(
                session_id=session_id,
                module=AuditModule.SYSTEM,
                decision=AuditDecision.ERROR,
                reason_code="audit_gap",
                details={
                    "dropped_events": count,
                    "overflow_policy": self._overflow_policy,
                    "queue_maxsize": self._queue.maxsize,
                    "note": (
                        "Audit queue saturated; this many decisions for this "
                        "session were not recorded (FR-AL-01 gap)."
                    ),
                },
            )
            try:
                await self._repo.append_chained(marker)
            except Exception as e:
                # Put the count back so the next flush retries rather than
                # losing the record of the loss.
                self._dropped[session_id] = self._dropped.get(session_id, 0) + count
                logger.error("audit_logger.gap_marker_failed", error=str(e))

    async def _write_batch(self, events: list[AuditEvent]) -> None:
        """
        Persist a batch, then fan out downstream.

        On batch failure, fall back to writing each event individually so one
        malformed event cannot discard the others (FR-AL-01).
        """
        try:
            finalized = await self._repo.append_chained_batch(events)
        except Exception as e:
            logger.error(
                "audit_logger.batch_write_error",
                error=str(e),
                events=len(events),
                fallback="per-event",
            )
            for event in events:
                await self._write(event)
            return

        for event in finalized:
            self._fan_out(event)

    async def _write(self, event: AuditEvent) -> None:
        # seq_no and prev_hash are assigned transactionally in the repository
        # so the per-session chain stays linear across workers (FR-AL-01).
        try:
            finalized = await self._repo.append_chained(event)
        except Exception as e:
            logger.error("audit_logger.db_write_error", error=str(e))
            return
        self._fan_out(finalized)

    def _fan_out(self, event: AuditEvent) -> None:
        """Forward downstream (fire-and-forget; the DB write is authoritative)."""
        if self._siem_url:
            asyncio.create_task(self._forward_siem(event))
        if self._kafka.active:
            asyncio.create_task(self._kafka.forward(event))

    async def _forward_siem(self, event: AuditEvent) -> None:
        try:
            payload = event.model_dump(mode="json")
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(self._siem_url, json=payload)
        except Exception as e:
            logger.warning("audit_logger.siem_forward_failed", error=str(e))

    # ── Session replay (FR-AL-02) ─────────────────────────────────────────────

    async def replay(self, session_id: str) -> SessionReplay:
        """Return ordered, verified event trail for a session."""
        events = await self._repo.get_session_events(session_id)
        chain_valid, issues = self._verify_chain(events)
        return SessionReplay(
            session_id=session_id,
            event_count=len(events),
            events=events,
            chain_valid=chain_valid,
            integrity_issues=issues,
        )

    @staticmethod
    def _verify_chain(events: list[AuditEvent]) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity of a sequence of events."""
        issues: list[str] = []
        prev_hash = ""
        for i, event in enumerate(events):
            expected = event.compute_hash(prev_hash)
            if event.event_hash != expected:
                issues.append(
                    f"Hash mismatch at seq {event.seq_no} (event {i}): "
                    f"expected {expected[:16]}… got {event.event_hash[:16]}…"
                )
            prev_hash = event.event_hash
        return len(issues) == 0, issues

    # ── Convenience factory methods ───────────────────────────────────────────

    def make_event(
        self,
        *,
        session_id: str,
        module: AuditModule,
        decision: AuditDecision,
        reason_code: str = "",
        details: dict[str, Any] | None = None,
        input_provenance: dict[str, Any] | None = None,
        agent_id: str = "default",
        context_id: str = "",
    ) -> AuditEvent:
        return AuditEvent(
            session_id=session_id,
            module=module,
            decision=decision,
            reason_code=reason_code,
            details=details or {},
            input_provenance=input_provenance or {},
            agent_id=agent_id,
            context_id=context_id,
        )
