"""
Audit event persistence — append-only ORM with hash-chain storage.
"""

from __future__ import annotations

from datetime import datetime

import structlog
from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from trust_mediator.db.base import AsyncSessionLocal, Base
from trust_mediator.models.audit_event import AuditEvent

logger = structlog.get_logger(__name__)


class AuditEventORM(Base):
    __tablename__ = "audit_events"
    # One chain position per session — makes cross-worker races detectable
    # (violators retry) instead of silently forking the chain.
    __table_args__ = (
        UniqueConstraint("session_id", "seq_no", name="uq_audit_session_seq"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    seq_no: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(50), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), default="")
    input_provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, default="")
    event_hash: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(100), default="default")
    context_id: Mapped[str] = mapped_column(String(36), default="")

    def to_pydantic(self) -> AuditEvent:
        from trust_mediator.models.audit_event import AuditDecision, AuditModule
        return AuditEvent(
            id=self.id,
            seq_no=self.seq_no,
            session_id=self.session_id,
            module=AuditModule(self.module),
            decision=AuditDecision(self.decision),
            reason_code=self.reason_code,
            input_provenance=self.input_provenance or {},
            details=self.details or {},
            timestamp=self.timestamp,
            prev_hash=self.prev_hash,
            event_hash=self.event_hash,
            agent_id=self.agent_id,
            context_id=self.context_id,
        )


def _to_orm(event: AuditEvent) -> AuditEventORM:
    return AuditEventORM(
        id=event.id,
        seq_no=event.seq_no,
        session_id=event.session_id,
        module=event.module.value,
        decision=event.decision.value,
        reason_code=event.reason_code,
        input_provenance=event.input_provenance,
        details=event.details,
        timestamp=event.timestamp,
        prev_hash=event.prev_hash,
        event_hash=event.event_hash,
        agent_id=event.agent_id,
        context_id=event.context_id,
    )


class AuditRepository:
    """Append-only audit event storage."""

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Append an already-finalized event (seq_no + hashes pre-set)."""
        async with AsyncSessionLocal() as session:
            session.add(_to_orm(event))
            await session.commit()
        return event

    async def append_chained(self, event: AuditEvent, max_retries: int = 5) -> AuditEvent:
        """
        Finalize and append an event, computing seq_no and prev_hash inside a
        DB transaction so the per-session hash chain stays linear across
        workers and replicas (FR-AL-01).

        The previous chain tail is read with a row lock (FOR UPDATE on
        PostgreSQL; SQLite serializes writers natively). If two writers race
        past the lock on an empty session, the (session_id, seq_no) unique
        constraint rejects the loser, which retries against the new tail.
        """
        for attempt in range(max_retries):
            try:
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        result = await session.execute(
                            select(AuditEventORM.seq_no, AuditEventORM.event_hash)
                            .where(AuditEventORM.session_id == event.session_id)
                            .order_by(AuditEventORM.seq_no.desc())
                            .limit(1)
                            .with_for_update()
                        )
                        row = result.first()
                        prev_seq, prev_hash = (row[0], row[1]) if row else (0, "")
                        finalized = event.finalize(seq_no=prev_seq + 1, prev_hash=prev_hash)
                        session.add(_to_orm(finalized))
                return finalized
            except IntegrityError:
                logger.info(
                    "audit_repo.chain_race_retry",
                    session_id=event.session_id,
                    attempt=attempt + 1,
                )
        raise RuntimeError(
            f"audit chain append failed after {max_retries} retries "
            f"(session={event.session_id})"
        )

    async def append_chained_batch(
        self, events: list[AuditEvent], max_retries: int = 5
    ) -> list[AuditEvent]:
        """
        Append many events in one transaction, preserving the per-session chain.

        Same integrity model as `append_chained` — the chain tail is still read
        under a row lock inside the transaction, and (session_id, seq_no) still
        rejects a racing writer. What changes is the amortisation: one lock plus
        one SELECT per *session per batch* instead of per event, and one commit
        instead of one per event.

        This is deliberately NOT per-process chain state. The tail is re-read
        from the database on every batch and every retry, so a second worker
        writing the same session stays correct; the in-memory chaining below
        only spans events inside a single locked transaction, where no other
        writer can interleave. Caching a chain head across transactions is what
        forked the chain before (see test_audit_chain_multiworker) — don't.

        Measured on the load harness this took audit throughput from ~140 to
        well above the request path's own ceiling; see benchmarks/results/load.md.
        """
        if not events:
            return []

        # Preserve arrival order within each session — that order is the chain.
        by_session: dict[str, list[AuditEvent]] = {}
        for event in events:
            by_session.setdefault(event.session_id, []).append(event)

        for attempt in range(max_retries):
            try:
                finalized: list[AuditEvent] = []
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        for session_id, session_events in by_session.items():
                            result = await session.execute(
                                select(AuditEventORM.seq_no, AuditEventORM.event_hash)
                                .where(AuditEventORM.session_id == session_id)
                                .order_by(AuditEventORM.seq_no.desc())
                                .limit(1)
                                .with_for_update()
                            )
                            row = result.first()
                            seq_no, prev_hash = (row[0], row[1]) if row else (0, "")

                            for event in session_events:
                                seq_no += 1
                                chained = event.finalize(
                                    seq_no=seq_no, prev_hash=prev_hash
                                )
                                prev_hash = chained.event_hash
                                session.add(_to_orm(chained))
                                finalized.append(chained)
                return finalized
            except IntegrityError:
                logger.info(
                    "audit_repo.batch_chain_race_retry",
                    sessions=len(by_session),
                    events=len(events),
                    attempt=attempt + 1,
                )
        raise RuntimeError(
            f"audit chain batch append failed after {max_retries} retries "
            f"({len(events)} events across {len(by_session)} sessions)"
        )

    async def get_session_events(self, session_id: str) -> list[AuditEvent]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AuditEventORM)
                .where(AuditEventORM.session_id == session_id)
                .order_by(AuditEventORM.seq_no.asc())
            )
            return [row.to_pydantic() for row in result.scalars()]

    async def get_last_event(self, session_id: str) -> AuditEvent | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AuditEventORM)
                .where(AuditEventORM.session_id == session_id)
                .order_by(AuditEventORM.seq_no.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            return row.to_pydantic() if row else None

    async def get_global_seq_no(self) -> int:
        """Return the current maximum seq_no across all sessions."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AuditEventORM.seq_no)
                .order_by(AuditEventORM.seq_no.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            return row if row is not None else 0
