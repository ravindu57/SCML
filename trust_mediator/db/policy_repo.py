"""
Policy version persistence — ORM model and repository.
Versioned policy storage with rollback support (FR-CP-01).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from trust_mediator.db.base import AsyncSessionLocal, Base


class PolicyVersionORM(Base):
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    policy_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_shadow: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class PolicyRepository:
    """CRUD for declarative security policy with versioning."""

    async def get_active_policy(self) -> dict[str, Any] | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .where(PolicyVersionORM.is_active == True)  # noqa: E712
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            return row.policy_data if row else None

    async def get_active_version(self) -> PolicyVersionORM | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .where(PolicyVersionORM.is_active == True)  # noqa: E712
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()

    async def create_version(
        self,
        policy_data: dict[str, Any],
        description: str = "",
        created_by: str = "system",
        activate: bool = True,
        shadow: bool = False,
    ) -> PolicyVersionORM:
        async with AsyncSessionLocal() as session:
            # Get next version number
            result = await session.execute(
                select(PolicyVersionORM).order_by(PolicyVersionORM.version_number.desc()).limit(1)
            )
            last = result.scalar_one_or_none()
            next_version = (last.version_number + 1) if last else 1

            if activate:
                # Deactivate all existing
                existing = await session.execute(select(PolicyVersionORM).where(PolicyVersionORM.is_active == True))  # noqa: E712
                for row in existing.scalars():
                    row.is_active = False

            new_version = PolicyVersionORM(
                id=str(uuid.uuid4()),
                version_number=next_version,
                policy_data=policy_data,
                description=description,
                is_active=activate,
                is_shadow=shadow,
                created_by=created_by,
                activated_at=datetime.now(timezone.utc) if activate else None,
            )
            session.add(new_version)
            await session.commit()
            await session.refresh(new_version)
            return new_version

    async def rollback(self, version_id: str) -> bool:
        """Reactivate a previous version, deactivating the current one."""
        async with AsyncSessionLocal() as session:
            # Deactivate current
            existing = await session.execute(select(PolicyVersionORM).where(PolicyVersionORM.is_active == True))  # noqa: E712
            for row in existing.scalars():
                row.is_active = False

            # Activate target
            target_result = await session.execute(
                select(PolicyVersionORM).where(PolicyVersionORM.id == version_id)
            )
            target = target_result.scalar_one_or_none()
            if not target:
                return False
            target.is_active = True
            target.activated_at = datetime.now(timezone.utc)
            await session.commit()
            return True

    async def list_versions(self, limit: int = 20) -> list[PolicyVersionORM]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(limit)
            )
            return list(result.scalars())
