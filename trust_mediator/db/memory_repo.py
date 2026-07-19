"""
Memory record persistence — ORM model and repository.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, String, Text, select, update
from sqlalchemy.orm import Mapped, mapped_column

from trust_mediator.db.base import AsyncSessionLocal, Base
from trust_mediator.models.memory_record import MemoryRecord, MemoryStatus


class MemoryRecordORM(Base):
    __tablename__ = "memory_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_provenance: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    trust_label: Mapped[str] = mapped_column(String(50), nullable=False)
    integrity_score: Mapped[float] = mapped_column(Float, default=0.0)
    scan_score: Mapped[float] = mapped_column(Float, default=0.0)
    provenance_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(20), default="quarantined", index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    quarantine_reason: Mapped[str] = mapped_column(Text, default="")
    consistency_flags: Mapped[list] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    agent_id: Mapped[str] = mapped_column(String(100), default="default", index=True)
    session_id: Mapped[str] = mapped_column(String(36), default="", index=True)

    def to_pydantic(self) -> MemoryRecord:
        from trust_mediator.models.context_envelope import Provenance, TrustLabel
        return MemoryRecord(
            id=self.id,
            content=self.content,
            source_provenance=Provenance(**self.source_provenance),
            trust_label=TrustLabel(self.trust_label),
            integrity_score=self.integrity_score,
            scan_score=self.scan_score,
            provenance_score=self.provenance_score,
            status=MemoryStatus(self.status),
            content_hash=self.content_hash,
            quarantine_reason=self.quarantine_reason,
            consistency_flags=self.consistency_flags or [],
            metadata=self.metadata_ or {},
            created_at=self.created_at,
            last_verified_at=self.last_verified_at,
        )


class MemoryRepository:
    """CRUD operations for MemoryRecord."""

    async def save(self, record: MemoryRecord, agent_id: str = "default") -> MemoryRecord:
        async with AsyncSessionLocal() as session:
            orm = MemoryRecordORM(
                id=record.id,
                content=record.content,
                source_provenance=record.source_provenance.model_dump(mode="json"),
                trust_label=record.trust_label.value,
                integrity_score=record.integrity_score,
                scan_score=record.scan_score,
                provenance_score=record.provenance_score,
                status=record.status.value,
                content_hash=record.content_hash,
                quarantine_reason=record.quarantine_reason,
                consistency_flags=record.consistency_flags,
                metadata_=record.metadata,
                created_at=record.created_at,
                last_verified_at=record.last_verified_at,
                agent_id=agent_id,
                session_id=record.source_provenance.session_id,
            )
            session.add(orm)
            await session.commit()
            return record

    async def get(self, memory_id: str) -> MemoryRecord | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(MemoryRecordORM).where(MemoryRecordORM.id == memory_id)
            )
            orm = result.scalar_one_or_none()
            return orm.to_pydantic() if orm else None

    async def update_status(
        self, memory_id: str, status: MemoryStatus, reason: str = ""
    ) -> None:
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(MemoryRecordORM)
                .where(MemoryRecordORM.id == memory_id)
                .values(status=status.value, quarantine_reason=reason)
            )
            await session.commit()

    async def list_quarantined(self, agent_id: str = "default") -> list[MemoryRecord]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(MemoryRecordORM).where(
                    MemoryRecordORM.status == MemoryStatus.QUARANTINED.value,
                    MemoryRecordORM.agent_id == agent_id,
                )
            )
            return [row.to_pydantic() for row in result.scalars()]

    async def list_active(self, agent_id: str = "default") -> list[MemoryRecord]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(MemoryRecordORM).where(
                    MemoryRecordORM.status == MemoryStatus.ACTIVE.value,
                    MemoryRecordORM.agent_id == agent_id,
                )
            )
            return [row.to_pydantic() for row in result.scalars()]

    async def update_verified_at(self, memory_id: str) -> None:
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(MemoryRecordORM)
                .where(MemoryRecordORM.id == memory_id)
                .values(last_verified_at=datetime.now(timezone.utc))
            )
            await session.commit()
