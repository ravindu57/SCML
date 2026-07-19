"""
Audit event persistence — append-only ORM with hash-chain storage.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from trust_mediator.db.base import AsyncSessionLocal, Base
from trust_mediator.models.audit_event import AuditEvent


class AuditEventORM(Base):
    __tablename__ = "audit_events"

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


class AuditRepository:
    """Append-only audit event storage."""

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Append a finalized event (seq_no + hashes set by AuditLogger)."""
        async with AsyncSessionLocal() as session:
            orm = AuditEventORM(
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
            session.add(orm)
            await session.commit()
        return event

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
