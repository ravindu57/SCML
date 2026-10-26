"""
Tenant isolation beyond policy (security review Sec #6, Sec #12; NFR-SEC-02).

Policy was key-bound per tenant (test_tenant_policy.py), but nothing else was:

  - **Memory** had no tenant. Company B could read company A's records by id,
    see A's quarantine queue, and A's memories fed B's consistency check. After
    the admin-key split, B's admin could release or purge A's quarantine.
  - **Audit** chains are keyed by the client's session id, so two companies
    using "s1" shared one chain and could replay each other's decisions.
  - **gRPC** mediated every call against the `default` tenant.
  - **Rate limits** were bucketed by `agent:tool`, so two companies' "ops"
    agents exhausted one bucket.

Each test below fails on the code before the fix.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.api.dependencies import get_pipeline
from trust_mediator.config import settings
from trust_mediator.core.tenancy import InvalidSessionId, scoped_session
from trust_mediator.db.audit_repo import AuditRepository
from trust_mediator.db.base import Base, engine
from trust_mediator.db.memory_repo import MemoryRecordORM, MemoryRepository
from trust_mediator.models.audit_event import AuditDecision, AuditEvent, AuditModule
from trust_mediator.models.context_envelope import Provenance, TrustLabel
from trust_mediator.models.memory_record import MemoryRecord, MemoryStatus

ACME, GLOBEX = "sk-acme-data", "sk-globex-data"
ACME_ADMIN, GLOBEX_ADMIN = "sk-acme-admin", "sk-globex-admin"


@pytest.fixture
async def fresh_memory_table():
    async with engine.begin() as conn:
        await conn.run_sync(MemoryRecordORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(MemoryRecordORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setattr(settings, "api_keys_raw", f"acme@ops:{ACME},globex@ops:{GLOBEX}")
    monkeypatch.setattr(
        settings, "admin_api_keys_raw", f"acme@sec:{ACME_ADMIN},globex@sec:{GLOBEX_ADMIN}"
    )


@pytest.fixture
async def client(keyed):
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        yield c


def _h(key):
    return {"X-API-Key": key}


async def _seed(tenant: str, status: MemoryStatus, content: str = "Q3 budget is 4M.") -> str:
    import hashlib

    record = MemoryRecord(
        content=content,
        source_provenance=Provenance(source="test", session_id="s1"),
        trust_label=TrustLabel.TRUSTED_INSTRUCTION,
        status=status,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )
    await MemoryRepository().save(record, agent_id="ops", tenant_id=tenant)
    return record.id


# ── Memory ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestMemoryIsTenantScoped:
    async def test_another_tenant_cannot_read_a_record_by_id(self, fresh_memory_table, client):
        rid = await _seed("acme", MemoryStatus.ACTIVE)
        theirs = await client.post("/v1/mediate/memory/read", json={"memory_id": rid}, headers=_h(GLOBEX))
        assert theirs.status_code == 200
        assert theirs.json()["verified"] is False
        assert theirs.json()["reason"] == "memory_not_found"
        assert theirs.json()["content"] is None
        ours = await client.post("/v1/mediate/memory/read", json={"memory_id": rid}, headers=_h(ACME))
        assert ours.json()["verified"] is True

    async def test_quarantine_queue_is_per_tenant(self, fresh_memory_table, client):
        rid = await _seed("acme", MemoryStatus.QUARANTINED, "poison payload")
        theirs = await client.get("/v1/mediate/memory/quarantined", headers=_h(GLOBEX))
        assert theirs.json()["records"] == []
        ours = await client.get("/v1/mediate/memory/quarantined", headers=_h(ACME))
        assert [r["id"] for r in ours.json()["records"]] == [rid]

    async def test_another_tenants_admin_cannot_release(self, fresh_memory_table, client):
        rid = await _seed("acme", MemoryStatus.QUARANTINED)
        r = await client.post(f"/v1/mediate/memory/quarantined/{rid}/release", headers=_h(GLOBEX_ADMIN))
        assert r.status_code == 404
        assert (await MemoryRepository().get(rid, tenant_id="acme")).status == MemoryStatus.QUARANTINED
        ok = await client.post(f"/v1/mediate/memory/quarantined/{rid}/release", headers=_h(ACME_ADMIN))
        assert ok.status_code == 200

    async def test_another_tenants_admin_cannot_purge(self, fresh_memory_table, client):
        rid = await _seed("acme", MemoryStatus.QUARANTINED)
        r = await client.delete(f"/v1/mediate/memory/quarantined/{rid}", headers=_h(GLOBEX_ADMIN))
        assert r.status_code == 404
        assert (await MemoryRepository().get(rid, tenant_id="acme")).status == MemoryStatus.QUARANTINED

    async def test_purge_refuses_an_active_record(self, fresh_memory_table, client):
        """Purge said 'quarantined or rejected' but accepted anything."""
        rid = await _seed("acme", MemoryStatus.ACTIVE)
        r = await client.delete(f"/v1/mediate/memory/quarantined/{rid}", headers=_h(ACME_ADMIN))
        assert r.status_code == 404
        assert (await MemoryRepository().get(rid, tenant_id="acme")).status == MemoryStatus.ACTIVE

    async def test_purge_of_an_unknown_id_is_not_reported_as_success(self, fresh_memory_table, client):
        r = await client.delete("/v1/mediate/memory/quarantined/no-such-id", headers=_h(ACME_ADMIN))
        assert r.status_code == 404

    async def test_release_is_a_single_conditional_transition(self, fresh_memory_table, client):
        rid = await _seed("acme", MemoryStatus.QUARANTINED)
        first = await client.post(f"/v1/mediate/memory/quarantined/{rid}/release", headers=_h(ACME_ADMIN))
        second = await client.post(f"/v1/mediate/memory/quarantined/{rid}/release", headers=_h(ACME_ADMIN))
        assert (first.status_code, second.status_code) == (200, 404)

    async def test_writes_are_stored_under_the_keys_tenant(self, fresh_memory_table, client):
        r = await client.post(
            "/v1/mediate/memory/write",
            json={"content": "The team standup moved to 10am.", "agent_id": "ops"},
            headers=_h(GLOBEX),
        )
        rid = r.json()["record_id"]
        assert await MemoryRepository().get(rid, tenant_id="globex") is not None
        assert await MemoryRepository().get(rid, tenant_id="acme") is None

    async def test_the_body_cannot_name_a_tenant(self):
        from trust_mediator.api.routers.memory import MemoryReadBody, MemoryWriteBody

        assert "tenant_id" not in MemoryWriteBody.model_fields
        assert "tenant_id" not in MemoryReadBody.model_fields

    async def test_consistency_check_sees_only_the_tenants_memory(self, fresh_memory_table):
        await _seed("acme", MemoryStatus.ACTIVE, "acme fact")
        repo = MemoryRepository()
        assert [r.content for r in await repo.list_active("ops", tenant_id="acme")] == ["acme fact"]
        assert await repo.list_active("ops", tenant_id="globex") == []


# ── Audit / sessions ──────────────────────────────────────────────────────────


class TestSessionScoping:
    def test_default_tenant_keeps_raw_ids_so_old_chains_replay(self):
        assert scoped_session(settings.default_tenant, "s1") == "s1"

    def test_other_tenants_are_namespaced(self):
        assert scoped_session("acme", "s1") == "acme::s1"
        assert scoped_session("acme", "s1") != scoped_session("globex", "s1")

    def test_a_client_cannot_forge_another_tenants_namespace(self):
        with pytest.raises(InvalidSessionId):
            scoped_session(settings.default_tenant, "acme::s1")

    def test_scoped_ids_fit_the_session_columns(self):
        """VARCHAR(36) overflowed on PostgreSQL for any non-default tenant's
        UUID session, and the audit writer dropped every such event."""
        from trust_mediator.core.tenancy import MAX_SESSION_ID
        from trust_mediator.db.audit_repo import AuditEventORM

        longest = scoped_session("t" * 64, "s" * MAX_SESSION_ID)
        assert len(longest) <= AuditEventORM.__table__.c.session_id.type.length
        assert len(longest) <= MemoryRecordORM.__table__.c.session_id.type.length
        with pytest.raises(InvalidSessionId):
            scoped_session("acme", "s" * (MAX_SESSION_ID + 1))

    def test_embedded_requests_default_to_the_configured_tenant(self, monkeypatch):
        from trust_mediator.models.memory_record import MemoryReadRequest, MemoryWriteRequest

        monkeypatch.setattr(settings, "default_tenant", "hq")
        assert MemoryWriteRequest(content="x").tenant_id == "hq"
        assert MemoryReadRequest(memory_id="m").tenant_id == "hq"


@pytest.mark.asyncio
class TestAuditReplayIsTenantScoped:
    async def test_same_session_id_is_a_different_chain_per_tenant(self, client):
        import uuid

        sid = f"iso-{uuid.uuid4().hex[:12]}"  # the test DB persists across runs
        repo = AuditRepository()
        await repo.append_chained(AuditEvent(
            session_id=f"acme::{sid}", module=AuditModule.TOOL_POLICY,
            decision=AuditDecision.ALLOW, reason_code="acme-secret",
        ))
        ours = await client.get(f"/v1/audit/replay/{sid}", headers=_h(ACME))
        theirs = await client.get(f"/v1/audit/replay/{sid}", headers=_h(GLOBEX))
        assert [e["reason_code"] for e in ours.json()["events"]] == ["acme-secret"]
        assert theirs.json()["event_count"] == 0

    @pytest.mark.parametrize(
        "method,path,body",
        [
            ("GET", "/v1/audit/replay/acme::x", None),
            ("POST", "/v1/mediate/context", {"session_id": "acme::x", "content": "hi"}),
            ("POST", "/v1/mediate/tool-call", {"session_id": "acme::x", "tool_name": "t"}),
            ("POST", "/v1/mediate/output", {"session_id": "acme::x", "content": "hi"}),
            ("POST", "/v1/mediate/memory/write", {"session_id": "acme::x", "content": "hi"}),
            ("POST", "/v1/mediate/memory/read", {"session_id": "acme::x", "memory_id": "m"}),
        ],
    )
    async def test_reserved_separator_is_rejected_everywhere(self, client, method, path, body):
        r = await client.request(method, path, json=body, headers=_h(GLOBEX))
        assert r.status_code == 422, r.text

    async def test_mediation_events_land_in_the_callers_chain(self, client):
        seen = {}

        class _P:
            async def replay_session(self, sid):
                seen["sid"] = sid
                from trust_mediator.models.audit_event import SessionReplay

                return SessionReplay(session_id=sid, event_count=0, events=[], chain_valid=True)

        app = create_app()
        app.dependency_overrides[get_pipeline] = _P
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            await c.get("/v1/audit/replay/s9", headers=_h(GLOBEX))
        assert seen["sid"] == "globex::s9"


# ── Rate limit ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_buckets_are_per_tenant():
    from trust_mediator.models.tool_call import ToolCallRequest
    from trust_mediator.modules.tool_policy.engine import PolicyEngine
    from trust_mediator.modules.tool_policy.rate_limiter import InMemoryRateLimiter

    policy = {
        "agents": {
            "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
            "ops": {"allowed_tools": ["read"], "untrusted_arg_policy": "deny",
                    "rate_limits": {"tool_calls_per_minute": 2}},
        },
        "memory": {"integrity_score_threshold": 0.65},
    }

    class _Loader:
        async def get_policy(self, tenant_id="default"):
            return policy

        def invalidate_cache(self):
            pass

    engine_ = PolicyEngine(loader=_Loader(), rate_limiter=InMemoryRateLimiter())

    def call(tenant):
        return engine_.evaluate(ToolCallRequest(agent_id="ops", tool_name="read", tenant_id=tenant))

    assert (await call("acme")).is_allowed and (await call("acme")).is_allowed
    assert not (await call("acme")).is_allowed  # acme's bucket is spent
    assert (await call("globex")).is_allowed  # globex's is untouched


# ── gRPC ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_grpc_resolves_the_tenant_from_the_key(keyed):
    pytest.importorskip("grpc")
    from trust_mediator.api.grpc.server import MediationServicer

    seen = {}

    class _Pipeline:
        async def process_tool_call(self, req):
            seen["tenant"], seen["session"] = req.tenant_id, req.session_id
            return SimpleNamespace(is_allowed=False, requires_approval=False, reason="",
                                   reason_code=SimpleNamespace(value="deny"),
                                   approver_required=False, approval_id=None)

    class _Ctx:
        def invocation_metadata(self):
            return (("x-api-key", GLOBEX),)

        async def abort(self, code, msg):
            raise AssertionError(msg)

    request = SimpleNamespace(arguments_json="", session_id="s1", agent_id="ops", tool_name="t",
                              argument_trust_labels={}, is_irreversible=False, is_high_impact=False)
    await MediationServicer(_Pipeline()).MediateToolCall(request, _Ctx())
    assert seen == {"tenant": "globex", "session": "globex::s1"}


# ── Migration ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pre_tenancy_memory_table_is_migrated(fresh_memory_table):
    from sqlalchemy import inspect, text

    from trust_mediator.db.base import _migrate_memory_tenant_column

    async with engine.begin() as conn:
        await conn.run_sync(MemoryRecordORM.__table__.drop)
        await conn.execute(text(
            "CREATE TABLE memory_records (id VARCHAR(36) PRIMARY KEY, content TEXT NOT NULL)"
        ))
        await conn.execute(text("INSERT INTO memory_records (id, content) VALUES ('old', 'x')"))
    await _migrate_memory_tenant_column()
    await _migrate_memory_tenant_column()  # idempotent
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda c: {x["name"] for x in inspect(c).get_columns("memory_records")})
        tenant = (await conn.execute(text("SELECT tenant_id FROM memory_records WHERE id='old'"))).scalar()
    assert "tenant_id" in cols and tenant == "default"


@pytest.mark.asyncio
async def test_a_purged_record_is_not_requarantined_by_a_racing_read(fresh_memory_table):
    """The read path's quarantine is conditional on the record still being ACTIVE."""
    rid = await _seed("acme", MemoryStatus.REJECTED)
    repo = MemoryRepository()
    assert await repo.update_status(rid, MemoryStatus.PURGED, "purge", tenant_id="acme")
    changed = await repo.update_status(
        rid, MemoryStatus.QUARANTINED, "mismatch", tenant_id="acme",
        from_status=(MemoryStatus.ACTIVE,),
    )
    assert changed is False
    assert (await repo.get(rid, tenant_id="acme")).status == MemoryStatus.PURGED
