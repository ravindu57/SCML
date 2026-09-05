"""
Policy version persistence — ORM model and repository.
Versioned policy storage with rollback support (FR-CP-01).
"""

from __future__ import annotations

import asyncio
import random
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from trust_mediator.db.base import AsyncSessionLocal, Base

logger = structlog.get_logger(__name__)


class PolicyVersionORM(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (
        # Optimistic concurrency for per-agent edits. A writer records the
        # version it read into base_version_id, so only one writer can
        # successfully base a change on a given version — the loser gets
        # IntegrityError and retries against the new document.
        #
        # A unique constraint on version_number alone does NOT work, and the
        # failure is subtle: the document was read from the *active* row while
        # the number came from max(version_number), and those diverge under
        # concurrency. A writer could read v3, find max=4, write v5 — no
        # collision, and every agent added in v4 silently erased. Measured:
        # 8 concurrent updates, v5 built from v3, one agent lost.
        #
        # NULL is allowed and repeats: whole-document PUTs do not participate,
        # and NULLs do not collide in a unique index on SQLite or PostgreSQL.
        UniqueConstraint("base_version_id", name="uq_policy_base_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    #: The policy tenant this version belongs to. Every policy operation is
    #: scoped by tenant, so tenant A's agents and versions never collide with
    #: tenant B's. The concurrency pair (active row, base_version_id) is
    #: meaningful only within one tenant: two tenants can each base a write on
    #: their own distinct active row without a unique-constraint collision.
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default", index=True, server_default="default"
    )
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
    #: The version this one was derived from, for per-agent edits. NULL for
    #: whole-document writes, which replace rather than derive.
    base_version_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )


class PolicyRepository:
    """CRUD for declarative security policy with versioning."""

    async def get_active_policy(self, tenant_id: str = "default") -> dict[str, Any] | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .where(
                    PolicyVersionORM.is_active == True,  # noqa: E712
                    PolicyVersionORM.tenant_id == tenant_id,
                )
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            return row.policy_data if row else None

    async def get_active_version(self, tenant_id: str = "default") -> PolicyVersionORM | None:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .where(
                    PolicyVersionORM.is_active == True,  # noqa: E712
                    PolicyVersionORM.tenant_id == tenant_id,
                )
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
        tenant_id: str = "default",
    ) -> PolicyVersionORM:
        async with AsyncSessionLocal() as session:
            # Get next version number within this tenant
            result = await session.execute(
                select(PolicyVersionORM)
                .where(PolicyVersionORM.tenant_id == tenant_id)
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(1)
            )
            last = result.scalar_one_or_none()
            next_version = (last.version_number + 1) if last else 1

            if activate:
                # Deactivate all existing within this tenant
                existing = await session.execute(
                    select(PolicyVersionORM).where(
                        PolicyVersionORM.is_active == True,  # noqa: E712
                        PolicyVersionORM.tenant_id == tenant_id,
                    )
                )
                for row in existing.scalars():
                    row.is_active = False

            new_version = PolicyVersionORM(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
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

    async def upsert_agent(
        self,
        agent_id: str,
        agent_policy: dict[str, Any] | None,
        description: str = "",
        created_by: str = "api",
        max_retries: int = 10,
        tenant_id: str = "default",
    ) -> PolicyVersionORM:
        """Replace one agent's entry, leaving every other agent untouched.

        Read-modify-write of the whole document happens **inside one
        transaction**, which is the entire point. Doing it in the router — read
        the active policy, edit one key, call create_version — would reintroduce
        the bug this endpoint exists to fix, only harder to see: two teams both
        read version N, both write N+1, and the second silently erases the
        first's agent. The window is milliseconds rather than permanent, so it
        passes every simple test and fails in production.

        FOR UPDATE locks the active row on PostgreSQL but is a **no-op on
        SQLite**, so the real guard is the unique constraint on
        `base_version_id`: a writer records the version it read, and only one
        writer can base a change on a given version. The loser gets
        IntegrityError and retries against the document that won.

        Constraining `version_number` instead does not work. The document is
        read from the *active* row while the number comes from
        `max(version_number)`, and those diverge under load — a writer can read
        v3, find max=4, write v5, and silently erase everything v4 added. That
        was measured, not theorised.

        Exhausting the retries raises. Nothing is written, which is the right
        failure for a policy change: a caller that sees an error can retry, a
        caller whose write vanished cannot know to.

        ``agent_policy=None`` deletes the agent. Deleting one that is not there
        is not an error — the caller's intent is already satisfied.
        """
        for attempt in range(max_retries):
            try:
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        result = await session.execute(
                            select(PolicyVersionORM)
                            .where(
                                PolicyVersionORM.is_active == True,  # noqa: E712
                                PolicyVersionORM.tenant_id == tenant_id,
                            )
                            .order_by(PolicyVersionORM.version_number.desc())
                            .limit(1)
                            .with_for_update()
                        )
                        active = result.scalar_one_or_none()
                        if active is None:
                            raise ValueError(
                                f"no active policy for tenant '{tenant_id}' — "
                                "write a whole document first (PUT /v1/policy)"
                            )

                        # Deep-copy: SQLAlchemy does not detect in-place
                        # mutation of a JSON column, so editing
                        # active.policy_data directly would also alter the row
                        # being superseded.
                        document: dict[str, Any] = deepcopy(active.policy_data)
                        agents = dict(document.get("agents") or {})
                        if agent_policy is None:
                            agents.pop(agent_id, None)
                        else:
                            agents[agent_id] = agent_policy
                        document["agents"] = agents

                        last = await session.execute(
                            select(PolicyVersionORM)
                            .where(PolicyVersionORM.tenant_id == tenant_id)
                            .order_by(PolicyVersionORM.version_number.desc())
                            .limit(1)
                        )
                        last_row = last.scalar_one_or_none()
                        next_version = (last_row.version_number + 1) if last_row else 1

                        existing = await session.execute(
                            select(PolicyVersionORM).where(
                                PolicyVersionORM.is_active == True,  # noqa: E712
                                PolicyVersionORM.tenant_id == tenant_id,
                            )
                        )
                        for row in existing.scalars():
                            row.is_active = False

                        new_version = PolicyVersionORM(
                            id=str(uuid.uuid4()),
                            tenant_id=tenant_id,
                            version_number=next_version,
                            policy_data=document,
                            description=description,
                            is_active=True,
                            is_shadow=False,
                            created_by=created_by,
                            activated_at=datetime.now(timezone.utc),
                            # The token that makes this safe: whoever else read
                            # the same version loses on the unique constraint
                            # and retries against the document that won.
                            base_version_id=active.id,
                        )
                        session.add(new_version)

                    await session.refresh(new_version)
                    return new_version
            except IntegrityError:
                logger.info(
                    "policy_repo.version_race_retry",
                    agent_id=agent_id,
                    attempt=attempt + 1,
                )
                # Jittered backoff. Without it every loser retries in lockstep
                # and collides again on the same base version, so contention
                # does not decay — measured as ~1 in 6 runs of eight concurrent
                # updates exhausting retries. The jitter matters more than the
                # delay: it breaks the synchronisation, not the throughput.
                await asyncio.sleep(random.uniform(0, 0.01) * (attempt + 1))
        raise RuntimeError(
            f"could not update agent {agent_id!r} after {max_retries} attempts "
            "of concurrent policy writes. Nothing was written — retry the "
            "update rather than assuming it applied."
        )

    async def rollback(self, version_id: str, tenant_id: str = "default") -> bool:
        """Reactivate a previous version of the caller's tenant, deactivating the current one.

        The target must belong to the caller's tenant: another tenant's version
        id is treated as not found, so a tenant cannot roll the *global* policy
        (or another company's) onto its own request path.
        """
        async with AsyncSessionLocal() as session:
            # Deactivate current versions of this tenant
            existing = await session.execute(
                select(PolicyVersionORM).where(
                    PolicyVersionORM.is_active == True,  # noqa: E712
                    PolicyVersionORM.tenant_id == tenant_id,
                )
            )
            for row in existing.scalars():
                row.is_active = False

            # Activate target — must belong to the caller's tenant
            target_result = await session.execute(
                select(PolicyVersionORM).where(PolicyVersionORM.id == version_id)
            )
            target = target_result.scalar_one_or_none()
            if not target or target.tenant_id != tenant_id:
                return False
            target.is_active = True
            target.activated_at = datetime.now(timezone.utc)
            await session.commit()
            return True

    async def list_versions(self, limit: int = 20, tenant_id: str = "default") -> list[PolicyVersionORM]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyVersionORM)
                .where(PolicyVersionORM.tenant_id == tenant_id)
                .order_by(PolicyVersionORM.version_number.desc())
                .limit(limit)
            )
            return list(result.scalars())
