"""
FR-AL-01 audit completeness (security review Sec #9, E4).

Four ways a decision, or tampering with one, used to leave no trace:

1. The hash covered neither `agent_id`, `context_id` nor `input_provenance`, so
   any of them could be rewritten without breaking the chain (E4). Events now
   carry `hash_version`; v2 hashes every field, and v1 chains still verify.
2. A failed database write was logged and nothing else. A queue overflow left
   an `audit_gap` marker in the session's chain; a write failure left none.
3. An exception escaping a mediation call reached the client as a 500 with
   nothing in the chain.
4. Admin actions (policy writes and rollback, quarantine release and purge)
   were not audited at all. They now go to a per-tenant control-plane chain
   no client session can reach.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.api.dependencies import get_audit_logger, get_policy_store
from trust_mediator.config import settings
from trust_mediator.core.tenancy import CONTROL_PLANE, control_session, scoped_session
from trust_mediator.db.audit_repo import AuditRepository
from trust_mediator.models.audit_event import AuditDecision, AuditEvent, AuditModule
from trust_mediator.modules.audit_log.logger import AuditLogger
from trust_mediator.modules.policy_store.store import PolicyStore

POLICY = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "ops": {"allowed_tools": ["read"], "untrusted_arg_policy": "deny"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}


@pytest.fixture(autouse=True)
async def _tables():
    """The audit table exists however this module is run (alone or in the suite)."""
    from trust_mediator.db.base import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def _event(**kw) -> AuditEvent:
    base = dict(session_id="s", module=AuditModule.TOOL_POLICY, decision=AuditDecision.ALLOW)
    base.update(kw)
    return AuditEvent(**base)


# ── 1. Hash coverage ──────────────────────────────────────────────────────────


class TestHashCoversEveryField:
    @pytest.mark.parametrize(
        "field,value",
        [("agent_id", "attacker"), ("context_id", "ctx-forged"),
         ("input_provenance", {"source": "forged"})],
    )
    def test_editing_a_previously_unhashed_field_breaks_the_chain(self, field, value):
        e = _event(agent_id="ops", context_id="ctx-1", input_provenance={"source": "tool"})
        sealed = e.finalize(seq_no=1, prev_hash="")
        tampered = sealed.model_copy(update={field: value})
        ok, issues = AuditLogger._verify_chain([tampered])
        assert not ok, f"{field} is still outside the hash"

    def test_v1_chains_written_before_v2_still_verify(self):
        e = _event(hash_version=1, agent_id="ops").finalize(seq_no=1, prev_hash="")
        e2 = _event(hash_version=1).finalize(seq_no=2, prev_hash=e.event_hash)
        assert AuditLogger._verify_chain([e, e2]) == (True, [])

    def test_a_v1_event_after_a_v2_event_is_flagged_as_a_downgrade(self):
        first = _event().finalize(seq_no=1, prev_hash="")
        # Relabelled v1 with its hash recomputed: a consistent forgery except
        # for the version going backwards.
        second = _event(hash_version=1, agent_id="attacker").finalize(seq_no=2, prev_hash=first.event_hash)
        ok, issues = AuditLogger._verify_chain([first, second])
        assert not ok and "downgrade" in issues[0]

    @pytest.mark.asyncio
    async def test_hash_version_round_trips_through_the_store(self):
        sid = f"hv-{uuid.uuid4().hex[:8]}"
        await AuditRepository().append_chained(_event(session_id=sid, agent_id="ops"))
        [stored] = await AuditRepository().get_session_events(sid)
        assert stored.hash_version == 2
        assert AuditLogger._verify_chain([stored])[0]


# ── 2. Write failures leave a gap marker ──────────────────────────────────────


class _FlakyRepo:
    """Fails every append until `healthy` is set, then records them."""

    def __init__(self):
        self.healthy = False
        self.appended: list[AuditEvent] = []

    async def append_chained(self, event):
        if not self.healthy:
            raise RuntimeError("database unavailable")
        self.appended.append(event)
        return event

    async def append_chained_batch(self, events):
        if not self.healthy:
            raise RuntimeError("database unavailable")
        self.appended.extend(events)
        return events


@pytest.mark.asyncio
async def test_a_failed_write_is_marked_in_the_sessions_chain():
    repo = _FlakyRepo()
    audit = AuditLogger(repo=repo)
    await audit._write_batch([_event(session_id="s1"), _event(session_id="s1")])
    await audit._flush_gap_markers()  # store still down: the count is kept
    assert repo.appended == []
    repo.healthy = True
    await audit._flush_gap_markers()
    [marker] = repo.appended
    assert marker.session_id == "s1" and marker.reason_code == "audit_gap"
    assert marker.details["cause"] == "write_failed"
    assert marker.details["dropped_events"] == 2


# ── 3. Pipeline exceptions are audited ────────────────────────────────────────


class _RecordingAudit(AuditLogger):
    def __init__(self):
        super().__init__(repo=_FlakyRepo())
        self.logged: list[AuditEvent] = []

    def log(self, event):
        self.logged.append(event)


@pytest.mark.asyncio
async def test_an_unexpected_exception_is_audited_before_it_propagates():
    from trust_mediator.core.pipeline import MediationPipeline
    from trust_mediator.models.context_envelope import ContextEnvelope, Provenance

    class _Broken:
        async def scan_async(self, envelope):
            raise RuntimeError("boom")

    audit = _RecordingAudit()
    pipeline = MediationPipeline(audit_logger=audit, scanner=_Broken())
    envelope = ContextEnvelope(session_id="s-exc", content="x", provenance=Provenance(source="tool_result"))
    with pytest.raises(RuntimeError):
        await pipeline.process_context(envelope)
    [event] = audit.logged
    assert (event.session_id, event.reason_code, event.decision) == (
        "s-exc", "pipeline_exception", AuditDecision.ERROR
    )
    assert event.details == {"stage": "context", "error_type": "RuntimeError"}


# ── 4. Admin actions ──────────────────────────────────────────────────────────


class TestControlPlaneChainIsUnreachableFromClients:
    def test_no_client_session_maps_onto_a_control_plane_session(self):
        assert scoped_session(settings.default_tenant, CONTROL_PLANE) != control_session(
            settings.default_tenant
        )
        assert "#" not in "acme"  # '#' is not a legal tenant character
        assert scoped_session("acme", "x") != control_session("acme")


@pytest.fixture
async def admin_env(monkeypatch):
    from trust_mediator.db.base import Base, engine
    from trust_mediator.db.policy_repo import PolicyVersionORM

    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(settings, "api_keys_raw", "acme@ops:sk-data")
    monkeypatch.setattr(settings, "admin_api_keys_raw", "acme@sec:sk-admin")
    store = PolicyStore()
    await store.create_version(POLICY, tenant_id="acme")
    audit = _RecordingAudit()
    app = create_app()
    app.dependency_overrides[get_policy_store] = lambda: store
    app.dependency_overrides[get_audit_logger] = lambda: audit
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c, audit
    app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestAdminActionsAreAudited:
    async def test_successful_policy_write(self, admin_env):
        client, audit = admin_env
        r = await client.put("/v1/policy", json={"policy_data": POLICY}, headers={"X-API-Key": "sk-admin"})
        assert r.status_code == 200
        [e] = audit.logged
        assert e.session_id == control_session("acme")
        assert (e.reason_code, e.decision) == ("policy_put", AuditDecision.ALLOW)
        assert e.details["principal"] == "sec" and e.details["version_id"] == r.json()["id"]

    async def test_refused_policy_write(self, admin_env):
        client, audit = admin_env
        r = await client.put("/v1/policy", json={"policy_data": {"agents": {}}}, headers={"X-API-Key": "sk-admin"})
        assert r.status_code == 422
        [e] = audit.logged
        assert (e.reason_code, e.decision) == ("policy_put", AuditDecision.REJECT)
        # The type, not the message: validation text can quote the submitted policy.
        assert e.details["error_type"] == "ValueError" and "error" not in e.details

    async def test_a_store_failure_is_recorded_as_an_error(self, admin_env, monkeypatch):
        client, audit = admin_env

        async def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(PolicyStore, "create_version", boom)
        with pytest.raises(RuntimeError):
            await client.put("/v1/policy", json={"policy_data": POLICY}, headers={"X-API-Key": "sk-admin"})
        [e] = audit.logged
        assert (e.reason_code, e.decision) == ("policy_put", AuditDecision.ERROR)

    async def test_agent_upsert_delete_and_rollback(self, admin_env):
        client, audit = admin_env
        h = {"X-API-Key": "sk-admin"}
        await client.put("/v1/policy/agents/ops", json={"agent_policy": {"allowed_tools": ["read"]}}, headers=h)
        await client.delete("/v1/policy/agents/ops", headers=h)
        await client.post("/v1/policy/rollback/no-such-version", headers=h)
        assert [(e.reason_code, e.decision) for e in audit.logged] == [
            ("agent_policy_put", AuditDecision.ALLOW),
            ("agent_policy_delete", AuditDecision.ALLOW),
            ("policy_rollback", AuditDecision.REJECT),
        ]

    async def test_control_plane_replay_is_admin_only_and_tenant_scoped(self, admin_env):
        client, _ = admin_env
        await AuditRepository().append_chained(_event(
            session_id=control_session("acme"), module=AuditModule.POLICY_STORE,
            reason_code=f"marker-{uuid.uuid4().hex[:6]}",
        ))
        assert (await client.get("/v1/audit/control-plane", headers={"X-API-Key": "sk-data"})).status_code == 403
        r = await client.get("/v1/audit/control-plane", headers={"X-API-Key": "sk-admin"})
        assert r.status_code == 200
        assert r.json()["session_id"] == control_session("acme") and r.json()["chain_valid"]


@pytest.mark.asyncio
async def test_release_and_purge_are_audited():
    from trust_mediator.api.dependencies import get_pipeline

    class _Memory:
        async def review_and_release(self, memory_id, reviewer="", tenant_id="default"):
            return True

        async def purge(self, memory_id, reason="", tenant_id="default"):
            return False

    audit = _RecordingAudit()

    class _P:
        _memory = _Memory()
        _audit = audit

    import contextlib

    with contextlib.ExitStack():
        app = create_app()
        app.dependency_overrides[get_pipeline] = _P
        orig_data, orig_admin = settings.api_keys_raw, settings.admin_api_keys_raw
        settings.api_keys_raw, settings.admin_api_keys_raw = "sk-d", "sec:sk-a"
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/v1/mediate/memory/quarantined/m1/release", headers={"X-API-Key": "sk-a"})
                await c.delete("/v1/mediate/memory/quarantined/m1", headers={"X-API-Key": "sk-a"})
        finally:
            settings.api_keys_raw, settings.admin_api_keys_raw = orig_data, orig_admin
    assert [(e.reason_code, e.decision, e.details["memory_id"]) for e in audit.logged] == [
        ("memory_release", AuditDecision.ALLOW, "m1"),
        ("memory_purge", AuditDecision.REJECT, "m1"),
    ]


@pytest.mark.asyncio
async def test_pre_v2_audit_table_is_migrated_as_v1():
    from sqlalchemy import text

    from trust_mediator.db.audit_repo import AuditEventORM
    from trust_mediator.db.base import Base, _migrate_audit_hash_version, engine

    async with engine.begin() as conn:
        await conn.run_sync(AuditEventORM.__table__.drop, checkfirst=True)
        await conn.execute(text("CREATE TABLE audit_events (id VARCHAR(36) PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO audit_events (id) VALUES ('old')"))
    try:
        await _migrate_audit_hash_version()
        await _migrate_audit_hash_version()  # idempotent
        async with engine.connect() as conn:
            v = (await conn.execute(text("SELECT hash_version FROM audit_events WHERE id='old'"))).scalar()
        assert v == 1
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE audit_events"))
            await conn.run_sync(Base.metadata.create_all)


class _CountingDownRepo(_FlakyRepo):
    def __init__(self):
        super().__init__()
        self.calls = 0

    async def append_chained(self, event):
        self.calls += 1
        return await super().append_chained(event)


@pytest.mark.asyncio
async def test_flush_stops_at_the_first_failure_and_keeps_every_count():
    """With the store down, one failing call per pass, not one per session."""
    repo = _CountingDownRepo()
    audit = AuditLogger(repo=repo)
    audit._write_failed.update({"a": 1, "b": 2, "c": 3})
    await audit._flush_gap_markers()
    assert repo.calls == 1
    assert audit._write_failed == {"a": 1, "b": 2, "c": 3}


def test_gap_counters_are_bounded(monkeypatch):
    """Client-chosen session ids cannot grow the maps without bound."""
    from trust_mediator.modules.audit_log import logger as mod

    monkeypatch.setattr(mod, "MAX_GAP_SESSIONS", 2)
    counts: dict[str, int] = {}
    for sid in ["s1", "s2", "s3", "s4", "s1"]:
        mod._count_gap(counts, sid)
    assert counts == {"s1": 2, "s2": 1, mod.OVERFLOW_GAP_SESSION: 2}
