"""
Database engine + declarative base.
Uses SQLAlchemy 2.0 async engine.
  - SQLite (aiosqlite) for local dev / tests
  - PostgreSQL (asyncpg) for production
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from trust_mediator.config import settings

# Create the async engine
engine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,
    pool_pre_ping=True,
    # SQLite needs connect_args; PostgreSQL does not
    connect_args={"check_same_thread": False}
    if "sqlite" in settings.database_url
    else {},
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


async def _migrate_policy_tenant_column() -> None:
    """Add ``policy_versions.tenant_id`` to databases created before tenancy."""
    await _add_tenant_column("policy_versions")


async def _migrate_memory_tenant_column() -> None:
    """Add ``memory_records.tenant_id`` (Sec #6). Existing rows become ``default``,
    which is where every pre-tenancy write was made from an unqualified key."""
    await _add_tenant_column("memory_records")


async def _add_tenant_column(table: str) -> None:
    """Add ``<table>.tenant_id`` to databases created before tenancy.

    ``create_all`` only creates *missing* tables; it does not add columns to
    existing ones, so a pre-tenancy deployment would boot with the new column
    in the ORM but not in the table and every policy query would 500. This
    runs after create_all and is idempotent: it inspects for the column and
    adds it (``TEXT NOT NULL DEFAULT 'default'``) plus its index when absent.
    ``ADD COLUMN`` with a non-null default is supported by both SQLite and
    PostgreSQL.
    """
    import structlog
    from sqlalchemy import inspect, text

    log = structlog.get_logger(__name__)
    # IF NOT EXISTS on PostgreSQL as a second guard behind the advisory lock
    # (create_all_tables runs migrations while holding it). SQLite has no
    # ADD COLUMN IF NOT EXISTS, but it is single-writer and dev-only here.
    guard = "IF NOT EXISTS " if "postgresql" in settings.database_url else ""
    async with engine.connect() as conn:
        def _columns(sync_conn) -> set[str]:
            return {c["name"] for c in inspect(sync_conn).get_columns(table)}

        cols = await conn.run_sync(_columns)
        if "tenant_id" in cols:
            return
        await conn.execute(
            text(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {guard}tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'"
            )
        )
        await conn.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS ix_{table}_tenant_id "
                f"ON {table} (tenant_id)"
            )
        )
        await conn.commit()
        log.info("db.migrated_tenant_column", table=table)


async def _widen_session_columns() -> None:
    """Widen ``session_id`` from VARCHAR(36) to VARCHAR(200) on PostgreSQL.

    Tenant-scoped session ids exceed 36 characters (see audit_repo). SQLite
    does not enforce VARCHAR lengths, so only PostgreSQL needs this.
    """
    if "postgresql" not in settings.database_url:
        return
    import structlog
    from sqlalchemy import inspect, text

    log = structlog.get_logger(__name__)
    async with engine.connect() as conn:
        for table in ("audit_events", "memory_records"):
            def _length(sync_conn, table=table):
                for c in inspect(sync_conn).get_columns(table):
                    if c["name"] == "session_id":
                        return getattr(c["type"], "length", None)
                return None

            length = await conn.run_sync(_length)
            if length is not None and length < 200:
                await conn.execute(
                    text(f"ALTER TABLE {table} ALTER COLUMN session_id TYPE VARCHAR(200)")
                )
                log.info("db.widened_session_id", table=table, from_length=length)
        await conn.commit()


async def create_all_tables() -> None:
    """
    Create all tables (idempotent, used at startup).

    Safe under multi-worker startup: on PostgreSQL a session advisory lock
    serializes concurrent workers (create_all's exists-check then create is
    not atomic — two racing workers otherwise crash on pg_type collisions).
    If creation still fails but every table exists afterwards, a sibling
    worker won the race and the failure is benign.
    """
    import structlog
    from sqlalchemy import text

    log = structlog.get_logger(__name__)
    is_postgres = "postgresql" in settings.database_url
    _LOCK_KEY = 0x7472757374  # arbitrary constant shared by all workers

    async with engine.connect() as conn:
        if is_postgres:
            await conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _LOCK_KEY})
        try:
            try:
                await conn.run_sync(Base.metadata.create_all)
                await conn.commit()
            except Exception as e:
                await conn.rollback()

                def _all_exist(sync_conn) -> bool:
                    from sqlalchemy import inspect

                    names = set(inspect(sync_conn).get_table_names())
                    return all(t in names for t in Base.metadata.tables)

                if await conn.run_sync(_all_exist):
                    log.warning("db.create_all_race_benign", error=str(e))
                else:
                    raise
            # Migrations run while the lock is held: two workers upgrading
            # together would otherwise both see a column missing, and the
            # second would crash at boot on "column already exists".
            await _migrate_policy_tenant_column()
            await _migrate_memory_tenant_column()
            await _widen_session_columns()
        finally:
            if is_postgres:
                await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_KEY})
                await conn.commit()


async def get_session() -> AsyncSession:  # type: ignore[return]
    """FastAPI dependency that yields a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
