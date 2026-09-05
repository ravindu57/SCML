"""
Key-bound tenant isolation (FR-CP-01, §5.2 mediação-data separation).

A single mediator instance may serve many companies. Each API key is bound to
a tenant (`acme@ops:sk-acme`), and every policy operation — control-plane
writes/reads and the data plane's tool-call authorisation — resolves against
the tenant derived **from the authenticated key**, never from anything a client
can put on the wire:

  - No mediation request model accepts a `tenant_id` field, so a caller cannot
    claim another company's policy namespace regardless of how the body is
    shaped. The router sets `tenant_id=caller.tenant`.
  - An unqualified key (the only kind that existed before tenancy) resolves to
    `TRUST_MEDIATOR_DEFAULT_TENANT`, so existing deployments behave exactly as
    they always did.
  - A tenant with no policy document of its own is **deny-all**, not
    unrestricted — §9's fail-closed applies at the tenant boundary just as at
    the agent boundary.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.api.auth import caller_for, tenant_for
from trust_mediator.api.dependencies import get_pipeline, get_policy_store
from trust_mediator.config import KeyEntry, parse_key_entries_with_tenant, settings
from trust_mediator.db.base import Base, engine
from trust_mediator.db.policy_repo import PolicyVersionORM
from trust_mediator.models.tool_call import PolicyDecisionCode, ToolCallRequest
from trust_mediator.modules.policy_store.store import PolicyStore
from trust_mediator.modules.tool_policy.engine import PolicyEngine
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader

ACME_A = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "ops": {"allowed_tools": ["read_a"], "untrusted_arg_policy": "allow"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}

GLOBEX_B = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "ops": {"allowed_tools": ["read_b"], "untrusted_arg_policy": "allow"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}

ACME_KEY, GLOBEX_KEY = "sk-acme", "sk-globex"


@pytest.fixture
async def fresh_policy_table():
    """A clean policy_versions table per test (mirrors test_policy_per_agent)."""
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)


class TestKeyParsing:
    """The four formats `TRUST_MEDIATOR_API_KEYS` accepts after tenancy."""

    def test_plain_bare_key_has_no_tenant(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "sk-abc123")
        assert settings.api_key_entries == [KeyEntry(None, None, "sk-abc123")]
        assert settings.api_keys == ["sk-abc123"]

    def test_named_key_keeps_its_legacy_shape(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-a,ops-bot:sk-b")
        assert settings.api_key_entries == [
            KeyEntry(None, "alice", "sk-a"),
            KeyEntry(None, "ops-bot", "sk-b"),
        ]
        assert settings.api_keys == ["sk-a", "sk-b"]

    def test_tenant_qualified_named_key(self):
        assert parse_key_entries_with_tenant("acme@ops:sk-acme") == [
            KeyEntry("acme", "ops", "sk-acme")
        ]

    def test_tenant_qualified_unnamed_key(self):
        assert parse_key_entries_with_tenant("acme@sk-acme") == [
            KeyEntry("acme", None, "sk-acme")
        ]

    def test_mixed_list_parses_cleanly(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "api_keys_raw",
            "acme@ops:sk-acme,globex@ops:sk-globex,bob:sk-b,sk-c",
        )
        assert settings.api_key_entries == [
            KeyEntry("acme", "ops", "sk-acme"),
            KeyEntry("globex", "ops", "sk-globex"),
            KeyEntry(None, "bob", "sk-b"),
            KeyEntry(None, None, "sk-c"),
        ]

    def test_a_bare_key_with_a_slash_is_not_tenant_qualified(self, monkeypatch):
        """A key whose own text happens to contain '@' before its colon is the
        documented residual ambiguity — a key whose text merely contains a
        slash, like the existing pinned test's `sk-abc/def:ghi`, must parse
        exactly as it always did."""
        monkeypatch.setattr(settings, "api_keys_raw", "sk-abc/def:ghi")
        assert settings.api_keys == ["sk-abc/def:ghi"]
        assert settings.api_key_entries == [KeyEntry(None, None, "sk-abc/def:ghi")]

    def test_unqualified_entries_resolve_to_default_tenant(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "alice:sk-a")
        monkeypatch.setattr(settings, "default_tenant", "freightco")
        assert tenant_for("sk-a") == "freightco"
        assert caller_for("sk-a").principal == "alice"


class TestCallerResolution:
    def test_qualified_key_maps_to_its_tenant(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "acme@ops:sk-acme,globex@ops:sk-globex")
        tenant_for(ACME_KEY) == "acme"
        assert caller_for(ACME_KEY) == ("acme", "ops")
        assert caller_for(GLOBEX_KEY) == ("globex", "ops")

    def test_unknown_key_resolves_to_none(self, monkeypatch):
        monkeypatch.setattr(settings, "api_keys_raw", "acme@ops:sk-acme")
        assert caller_for("sk-nope") is None
        assert tenant_for("sk-nope") is None


class TestStorageIsolation:
    """The same agent_id in two tenants is two different policy documents."""

    @pytest.mark.asyncio
    async def test_same_agent_id_differs_across_tenants(self, fresh_policy_table):
        s = PolicyStore()
        await s.create_version(ACME_A, description="acme base", tenant_id="acme")
        await s.create_version(GLOBEX_B, description="globex base", tenant_id="globex")

        assert (await s.get_active(tenant_id="acme"))["agents"]["ops"]["allowed_tools"] == ["read_a"]
        assert (await s.get_active(tenant_id="globex"))["agents"]["ops"]["allowed_tools"] == ["read_b"]

    @pytest.mark.asyncio
    async def test_writing_one_tenant_does_not_touch_another(self, fresh_policy_table):
        s = PolicyStore()
        await s.create_version(ACME_A, description="acme v1", tenant_id="acme")
        await s.create_version(GLOBEX_B, description="globex v1", tenant_id="globex")

        await s.create_version(ACME_A, description="acme v2", tenant_id="acme")

        assert (await s.get_active_version(tenant_id="acme")).version_number == 2
        assert (await s.get_active(tenant_id="globex"))["agents"]["ops"]["allowed_tools"] == ["read_b"]
        assert (await s.get_active_version(tenant_id="globex")).version_number == 1

    @pytest.mark.asyncio
    async def test_per_agent_update_is_scoped(self, fresh_policy_table):
        s = PolicyStore()
        await s.create_version(ACME_A, description="acme base", tenant_id="acme")
        await s.create_version(GLOBEX_B, description="globex base", tenant_id="globex")

        await s.upsert_agent(
            "ops", {"allowed_tools": ["read_a", "read_a2"]}, tenant_id="acme"
        )

        assert (await s.get_active(tenant_id="acme"))["agents"]["ops"]["allowed_tools"] == [
            "read_a", "read_a2"
        ]
        assert (await s.get_active(tenant_id="globex"))["agents"]["ops"]["allowed_tools"] == [
            "read_b"
        ]

    @pytest.mark.asyncio
    async def test_rollback_cannot_reach_another_tenant(self, fresh_policy_table):
        s = PolicyStore()
        v1 = await s.create_version(ACME_A, description="acme v1", tenant_id="acme")
        await s.create_version(ACME_A, description="acme v2", tenant_id="acme")
        g1 = await s.create_version(GLOBEX_B, description="globex v1", tenant_id="globex")

        # Roll back acme to its own v1 — globex unaffected.
        assert await s.rollback(v1.id, tenant_id="acme") is True
        assert (await s.get_active_version(tenant_id="acme")).id == v1.id
        assert (await s.get_active_version(tenant_id="globex")).id == g1.id

        # acme cannot roll globex's version onto its own path.
        assert await s.rollback(g1.id, tenant_id="acme") is False
        assert await s.rollback(v1.id, tenant_id="globex") is False

    @pytest.mark.asyncio
    async def test_version_numbers_are_per_tenant(self, fresh_policy_table):
        s = PolicyStore()
        await s.create_version(ACME_A, description="a1", tenant_id="acme")
        await s.create_version(ACME_A, description="a2", tenant_id="acme")
        await s.create_version(ACME_A, description="a3", tenant_id="acme")
        await s.create_version(GLOBEX_B, description="b1", tenant_id="globex")

        acme = await s.list_versions(tenant_id="acme")
        globex = await s.list_versions(tenant_id="globex")
        assert [v.version_number for v in acme] == [3, 2, 1]
        assert [v.version_number for v in globex] == [1]
        assert all(v.tenant_id == "acme" for v in acme)
        assert all(v.tenant_id == "globex" for v in globex)

    @pytest.mark.asyncio
    async def test_upsert_agent_requires_a_tenant_document(self, fresh_policy_table):
        """A tenant that never wrote a whole document has no active row to
        modify; the write is refused, not silently applied to default."""
        s = PolicyStore()
        await s.create_version(ACME_A, description="acme base", tenant_id="acme")
        with pytest.raises(ValueError, match="no active policy for tenant 'globex'"):
            await s.upsert_agent("ops", {"allowed_tools": ["x"]}, tenant_id="globex")


class TestDataPlaneIsolation:
    """The tool-call authorisation path resolves the tenant's document."""

    async def _engine_for(self, store: PolicyStore) -> PolicyEngine:
        return PolicyEngine(PolicyLoader(policy_repo=store._repo))

    @pytest.mark.asyncio
    async def test_same_agent_allowed_here_denied_there(self, fresh_policy_table):
        s = PolicyStore()
        await s.create_version(ACME_A, description="acme base", tenant_id="acme")
        await s.create_version(GLOBEX_B, description="globex base", tenant_id="globex")
        engine = await self._engine_for(s)

        req_a = ToolCallRequest(
            session_id="t", tool_name="read_a", agent_id="ops", tenant_id="acme"
        )
        req_b = ToolCallRequest(
            session_id="t", tool_name="read_a", agent_id="ops", tenant_id="globex"
        )
        assert (await engine.evaluate(req_a)).decision == PolicyDecisionCode.ALLOW
        assert (await engine.evaluate(req_b)).decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    @pytest.mark.asyncio
    async def test_tenant_with_no_policy_is_deny_all(self, fresh_policy_table):
        """A company that enrols no policy must be denied — §9 fail-closed at
        the tenant boundary. (checks `_TENANT_DENY_ALL` carries explicit [])"""
        s = PolicyStore()  # nothing seeded — even the default tenant is empty
        loader = PolicyLoader(policy_repo=s._repo)
        engine = PolicyEngine(loader)

        acme = await loader.get_policy(tenant_id="acme")
        assert acme["agents"]["default"]["allowed_tools"] == []

        denied = await engine.evaluate(
            ToolCallRequest(
                session_id="t", tool_name="web_search", agent_id="web_search_agent",
                tenant_id="acme",
            )
        )
        assert denied.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    @pytest.mark.asyncio
    async def test_default_tenant_still_gets_the_yaml_fallback(self, fresh_policy_table):
        """Unqualified keys land on `default`, which honours the gateway YAML —
        the behaviour every pre-tenancy deployment relies on."""
        s = PolicyStore()
        engine = PolicyEngine(PolicyLoader(policy_repo=s._repo))
        allowed = await engine.evaluate(
            ToolCallRequest(
                session_id="t", tool_name="web_search", agent_id="web_search_agent",
                arguments={"query": "latest AI research"},
            )
        )
        assert allowed.decision == PolicyDecisionCode.ALLOW


class TestApiTenantScoping:
    @pytest.fixture
    async def keyed_client(self, fresh_policy_table, monkeypatch):
        monkeypatch.setattr(
            settings, "api_keys_raw", f"acme@ops:{ACME_KEY},globex@ops:{GLOBEX_KEY}"
        )
        store = PolicyStore()
        await store.create_version(ACME_A, description="acme base", tenant_id="acme")
        await store.create_version(GLOBEX_B, description="globex base", tenant_id="globex")

        app = create_app()
        app.dependency_overrides[get_policy_store] = lambda: store
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as c:
            yield c, store
        app.dependency_overrides.clear()
        get_pipeline()._policy_engine._loader.invalidate_cache()

    def _key(self, key: str) -> dict:
        return {"X-API-Key": key}

    @pytest.mark.asyncio
    async def test_mediation_is_scoped_by_key_not_body(self, keyed_client):
        """The request body carries no tenant field and never could: the router
        sets `tenant_id` from the authenticated key."""
        client, _ = keyed_client
        forbidden_smuggle = {"tenant_id": "globex", "agent_id": "ops", "tool_name": "read_a"}

        acme = await client.post("/v1/mediate/tool-call", json=forbidden_smuggle, headers=self._key(ACME_KEY))
        assert acme.status_code == 200, acme.text
        assert acme.json()["decision"] == "allow"

        globex = await client.post("/v1/mediate/tool-call", json=forbidden_smuggle, headers=self._key(GLOBEX_KEY))
        assert globex.status_code == 200, globex.text
        assert "deny" in globex.json()["reason_code"], globex.json()

        globex_b = dict(forbidden_smuggle)
        globex_b["tool_name"] = "read_b"
        ok = await client.post("/v1/mediate/tool-call", json=globex_b, headers=self._key(GLOBEX_KEY))
        assert ok.json()["decision"] == "allow"

    def test_the_mediation_request_model_has_no_tenant_field(self):
        from trust_mediator.api.routers.mediate import ToolCallMediationRequest

        assert "tenant_id" not in ToolCallMediationRequest.model_fields, (
            "a client-facing field would let a caller name its own tenant"
        )

    @pytest.mark.asyncio
    async def test_control_plane_is_scoped_by_key(self, keyed_client):
        client, _ = keyed_client
        acme_get = await client.get("/v1/policy", headers=self._key(ACME_KEY))
        assert acme_get.status_code == 200
        assert acme_get.json()["tenant"] == "acme"
        assert acme_get.json()["policy"]["agents"]["ops"]["allowed_tools"] == ["read_a"]

        globex_get = await client.get("/v1/policy", headers=self._key(GLOBEX_KEY))
        assert globex_get.status_code == 200
        assert globex_get.json()["tenant"] == "globex"
        assert globex_get.json()["policy"]["agents"]["ops"]["allowed_tools"] == ["read_b"]

        # The same agent is a different document per tenant.
        acme_agent = await client.get("/v1/policy/agents/ops", headers=self._key(ACME_KEY))
        assert acme_agent.json()["tenant"] == "acme"
        assert acme_agent.json()["policy"]["allowed_tools"] == ["read_a"]

    async def test_a_tenant_cannot_create_another_tenant_by_editing_its_documents(
        self, keyed_client
    ):
        client, _ = keyed_client
        # A tenant-qualified key writing an agent only writes its own document.
        r = await client.put(
            "/v1/policy/agents/ops",
            json={"agent_policy": {"allowed_tools": ["read_a", "read_a2"]}},
            headers=self._key(ACME_KEY),
        )
        assert r.status_code == 200, r.text
        assert r.json()["created_by"] == "ops"

        # globex still has its own document and its own agent.
        globex = await client.get("/v1/policy/agents/ops", headers=self._key(GLOBEX_KEY))
        assert globex.json()["policy"]["allowed_tools"] == ["read_b"]

    @pytest.mark.asyncio
    async def test_whole_document_push_is_scoped(self, keyed_client):
        client, store = keyed_client
        r = await client.put(
            "/v1/policy",
            json={"policy_data": ACME_A, "description": "acme wholesale"},
            headers=self._key(ACME_KEY),
        )
        assert r.status_code == 200, r.text
        assert (await store.get_active_version(tenant_id="acme")).version_number == 2
        # globex untouched, still on v1.
        assert (await store.get_active_version(tenant_id="globex")).version_number == 1

    async def test_an_unkeyed_body_cannot_fake_a_tenant(self, keyed_client):
        """There is no tenant_id body field on the policy model either."""
        from trust_mediator.api.routers.policy import PolicyUpdateRequest

        assert "tenant_id" not in PolicyUpdateRequest.model_fields
        assert "tenant" not in PolicyUpdateRequest.model_fields

    @pytest.mark.asyncio
    async def test_default_agent_guard_holds_per_tenant(self, keyed_client):
        client, _ = keyed_client
        r = await client.put(
            "/v1/policy/agents/default",
            json={"agent_policy": {"allowed_tools": ["*"]}},
            headers=self._key(ACME_KEY),
        )
        assert r.status_code == 422