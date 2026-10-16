"""
FR-CP-03 / PRD §10 / NFR-SEC-02: control-plane writes need an admin key.
FR-CP-02: a shadow policy version is never enforced.

Before this, every data-plane key could also administer the mediator (security
review, Sec #2). The key an agent holds to mediate its own traffic could:

  - rewrite or roll back its tenant's policy, so an injected "add
    `transfer_funds` to your allow-list" needed only one HTTP call, and
  - release its own quarantined memory, re-admitting the poison FR-MI-03 caught.

Control-plane writes now take a key from a separate set,
`TRUST_MEDIATOR_ADMIN_API_KEYS[_FILE]`, with the same syntax, tenant binding
and rotation. The two sets never substitute for each other. With data-plane
keys configured and no admin keys, the control plane is **closed**, not open.

Separately (Sec E1), `shadow: true, activate: true` stored an active version
flagged as shadow. Nothing evaluates policy in shadow, so the data plane
enforced it while every listing called it shadow. That combination is now a
422, and promotion (rollback) clears the flag.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from trust_mediator.api import key_store
from trust_mediator.api.app import create_app
from trust_mediator.api.auth import _validate_admin, admin_caller_for
from trust_mediator.api.dependencies import get_pipeline, get_policy_store
from trust_mediator.config import settings
from trust_mediator.db.base import AsyncSessionLocal, Base, engine
from trust_mediator.db.policy_repo import PolicyVersionORM
from trust_mediator.modules.policy_store.store import PolicyStore

DATA_KEY = "sk-agent-data"
ADMIN_KEY = "sk-secops-admin"

POLICY = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "ops": {"allowed_tools": ["read_a"], "untrusted_arg_policy": "deny"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}
WIDER = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "ops": {"allowed_tools": ["read_a", "transfer_funds"], "untrusted_arg_policy": "deny"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}

#: Every control-plane write. Pinned so a new admin route, or one quietly moved
#: back to the data-plane dependency, fails here instead of in production.
ADMIN_ROUTES = {
    ("PUT", "/v1/policy"),
    ("PUT", "/v1/policy/agents/{agent_id}"),
    ("DELETE", "/v1/policy/agents/{agent_id}"),
    ("POST", "/v1/policy/rollback/{version_id}"),
    ("POST", "/v1/mediate/memory/quarantined/{memory_id}/release"),
    ("DELETE", "/v1/mediate/memory/quarantined/{memory_id}"),
}

#: One concrete request per admin route, with a body the handler would accept.
ADMIN_REQUESTS = [
    ("PUT", "/v1/policy", {"policy_data": WIDER}),
    ("PUT", "/v1/policy/agents/ops", {"agent_policy": {"allowed_tools": ["transfer_funds"]}}),
    ("DELETE", "/v1/policy/agents/ops", None),
    ("POST", "/v1/policy/rollback/some-version", None),
    ("POST", "/v1/mediate/memory/quarantined/mem-1/release", None),
    ("DELETE", "/v1/mediate/memory/quarantined/mem-1", None),
]


def _routes_using(dependency) -> set[tuple[str, str]]:
    from tests.unit.test_api_auth import _iter_api_routes

    def uses(dependant) -> bool:
        return dependant.call is dependency or any(uses(d) for d in dependant.dependencies)

    found = set()
    for r in _iter_api_routes(create_app().routes):
        if uses(r.dependant):
            for m in r.methods:
                found.add((m, r.path))
    return found


@pytest.fixture
async def fresh_policy_table():
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)


class _Memory:
    """Records what the admin handlers did, without a database."""

    def __init__(self):
        self.released: list[tuple[str, str]] = []
        self.purged: list[tuple[str, str]] = []

    async def review_and_release(self, memory_id, reviewer=""):
        self.released.append((memory_id, reviewer))
        return True

    async def purge(self, memory_id, reason=""):
        self.purged.append((memory_id, reason))


@pytest.fixture
async def env(fresh_policy_table, monkeypatch):
    """A keyed deployment: one data-plane key, one admin key, default tenant."""
    monkeypatch.setattr(settings, "api_keys_raw", f"agent:{DATA_KEY}")
    monkeypatch.setattr(settings, "admin_api_keys_raw", f"secops:{ADMIN_KEY}")
    store = PolicyStore()
    await store.create_version(POLICY, description="base", created_by="test")
    memory = _Memory()

    class _Pipeline:
        _memory = memory

    app = create_app()
    app.dependency_overrides[get_policy_store] = lambda: store
    app.dependency_overrides[get_pipeline] = _Pipeline
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c, store, memory
    app.dependency_overrides.clear()


async def _send(client, method, path, body, key=None):
    headers = {"X-API-Key": key} if key else {}
    return await client.request(method, path, json=body, headers=headers)


class TestAdminRouteSet:
    def test_exactly_the_control_plane_writes_require_an_admin_key(self):
        assert _routes_using(_validate_admin) == ADMIN_ROUTES

    def test_no_mediation_route_accepts_an_admin_key(self):
        for _, path in _routes_using(_validate_admin):
            assert not path.startswith("/v1/mediate/context")
            assert not path.startswith("/v1/mediate/tool-call")
            assert not path.startswith("/v1/mediate/output")


@pytest.mark.asyncio
class TestDataPlaneKeyCannotAdminister:
    """Each of these succeeded with the agent's own key before the fix."""

    @pytest.mark.parametrize("method,path,body", ADMIN_REQUESTS)
    async def test_fr_cp_03_data_key_is_refused(self, env, method, path, body):
        client, _, _ = env
        r = await _send(client, method, path, body, key=DATA_KEY)
        assert r.status_code == 403, f"{method} {path} -> {r.status_code}: {r.text}"

    @pytest.mark.parametrize("method,path,body", ADMIN_REQUESTS)
    async def test_no_key_is_401(self, env, method, path, body):
        client, _, _ = env
        r = await _send(client, method, path, body)
        assert r.status_code == 401

    async def test_policy_is_unchanged_after_a_refused_write(self, env):
        client, store, _ = env
        await _send(client, "PUT", "/v1/policy", {"policy_data": WIDER}, key=DATA_KEY)
        await _send(
            client, "PUT", "/v1/policy/agents/ops",
            {"agent_policy": {"allowed_tools": ["transfer_funds"]}}, key=DATA_KEY,
        )
        active = await store.get_active()
        assert active["agents"]["ops"]["allowed_tools"] == ["read_a"]
        assert len(await store.list_versions()) == 1

    async def test_fr_mi_05_agent_cannot_release_its_own_quarantined_memory(self, env):
        client, _, memory = env
        r = await _send(
            client, "POST", "/v1/mediate/memory/quarantined/mem-1/release", None, key=DATA_KEY
        )
        assert r.status_code == 403
        assert memory.released == []

    async def test_agent_cannot_purge_evidence(self, env):
        client, _, memory = env
        r = await _send(client, "DELETE", "/v1/mediate/memory/quarantined/mem-1", None, key=DATA_KEY)
        assert r.status_code == 403
        assert memory.purged == []

    async def test_refusal_does_not_reveal_that_the_key_is_live(self, env):
        """A data-plane key and garbage get the same answer."""
        client, _, _ = env
        a = await _send(client, "PUT", "/v1/policy", {"policy_data": WIDER}, key=DATA_KEY)
        b = await _send(client, "PUT", "/v1/policy", {"policy_data": WIDER}, key="sk-nonsense")
        assert (a.status_code, a.json()) == (b.status_code, b.json())


@pytest.mark.asyncio
class TestAdminKey:
    @pytest.mark.parametrize("method,path,body", ADMIN_REQUESTS)
    async def test_admin_key_gets_past_auth(self, env, method, path, body):
        client, _, _ = env
        r = await _send(client, method, path, body, key=ADMIN_KEY)
        # 404 for the unknown rollback target; everything else succeeds.
        assert r.status_code in (200, 404), f"{method} {path} -> {r.status_code}: {r.text}"

    async def test_admin_key_is_not_a_data_plane_key(self, env):
        """The sets do not substitute in either direction."""
        client, _, _ = env
        r = await _send(
            client, "POST", "/v1/mediate/tool-call",
            {"agent_id": "ops", "tool_name": "read_a"}, key=ADMIN_KEY,
        )
        assert r.status_code == 403

    async def test_version_records_the_admin_principal_not_the_body(self, env):
        client, _, _ = env
        r = await _send(
            client, "PUT", "/v1/policy",
            {"policy_data": POLICY, "created_by": "someone-else"}, key=ADMIN_KEY,
        )
        assert r.status_code == 200, r.text
        assert r.json()["created_by"] == "secops"

    async def test_release_records_the_admin_as_reviewer(self, env):
        client, _, memory = env
        r = await _send(
            client, "POST", "/v1/mediate/memory/quarantined/mem-1/release", None, key=ADMIN_KEY
        )
        assert r.status_code == 200
        assert memory.released == [("mem-1", "secops")]

    async def test_admin_key_is_bound_to_its_tenant(self, env, monkeypatch):
        client, store, _ = env
        monkeypatch.setattr(settings, "admin_api_keys_raw", f"acme@secops:{ADMIN_KEY}")
        r = await _send(client, "PUT", "/v1/policy", {"policy_data": WIDER}, key=ADMIN_KEY)
        assert r.status_code == 200, r.text
        assert (await store.get_active(tenant_id="acme"))["agents"]["ops"]["allowed_tools"] == [
            "read_a", "transfer_funds",
        ]
        # The default tenant's document is untouched.
        assert (await store.get_active())["agents"]["ops"]["allowed_tools"] == ["read_a"]


@pytest.mark.asyncio
class TestWhenTheControlPlaneIsOpen:
    async def test_data_keys_without_admin_keys_close_the_control_plane(
        self, env, monkeypatch
    ):
        """Not "fall back to data-plane keys": that is the escalation itself."""
        client, _, _ = env
        monkeypatch.setattr(settings, "admin_api_keys_raw", "")
        for method, path, body in ADMIN_REQUESTS:
            r = await _send(client, method, path, body, key=DATA_KEY)
            assert r.status_code == 403, f"{method} {path}"

    async def test_development_with_no_keys_at_all_stays_open(self, env, monkeypatch):
        """The demo scripts run keyless in development and push policy."""
        client, _, _ = env
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "admin_api_keys_raw", "")
        r = await _send(client, "PUT", "/v1/policy", {"policy_data": POLICY})
        assert r.status_code == 200, r.text
        assert r.json()["created_by"] == "anonymous"

    async def test_admin_keys_alone_still_require_a_key(self, env, monkeypatch):
        client, _, _ = env
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        r = await _send(client, "PUT", "/v1/policy", {"policy_data": POLICY})
        assert r.status_code == 401

    async def test_production_with_no_keys_is_closed(self, env, monkeypatch):
        client, _, _ = env
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "admin_api_keys_raw", "")
        r = await _send(client, "PUT", "/v1/policy", {"policy_data": POLICY})
        assert r.status_code == 401


class TestAdminKeyFile:
    """Same rotation semantics as TRUST_MEDIATOR_API_KEYS_FILE."""

    def test_rotation_and_revocation(self, tmp_path, monkeypatch):
        path = tmp_path / "admin-keys"
        path.write_text(f"secops:{ADMIN_KEY}\n")
        monkeypatch.setattr(settings, "admin_api_keys_raw", "")
        monkeypatch.setattr(settings, "admin_api_keys_file", str(path))
        key_store.reload_admin_keys()
        try:
            assert admin_caller_for(ADMIN_KEY).principal == "secops"
            path.write_text("")  # revoke everything
            key_store.reload_admin_keys()
            assert admin_caller_for(ADMIN_KEY) is None
        finally:
            monkeypatch.setattr(settings, "admin_api_keys_file", "")
            key_store.reload_admin_keys()

    def test_a_configured_file_closes_open_development(self, tmp_path, monkeypatch):
        from trust_mediator.api.auth import admin_open_access_allowed

        path = tmp_path / "admin-keys"
        path.write_text("")
        monkeypatch.setattr(settings, "env", "development")
        monkeypatch.setattr(settings, "api_keys_raw", "")
        monkeypatch.setattr(settings, "admin_api_keys_raw", "")
        monkeypatch.setattr(settings, "admin_api_keys_file", str(path))
        key_store.reload_admin_keys()
        try:
            assert admin_open_access_allowed() is False
        finally:
            monkeypatch.setattr(settings, "admin_api_keys_file", "")
            key_store.reload_admin_keys()

    def test_admin_key_is_not_read_through_the_generic_file_source(self):
        from trust_mediator.config import _NO_FILE_SOURCE

        assert "admin_api_keys_raw" in _NO_FILE_SOURCE


@pytest.mark.asyncio
class TestShadowIsNeverEnforced:
    async def test_fr_cp_02_active_shadow_is_refused(self, env):
        client, store, _ = env
        r = await _send(
            client, "PUT", "/v1/policy",
            {"policy_data": WIDER, "shadow": True, "activate": True}, key=ADMIN_KEY,
        )
        assert r.status_code == 422, r.text
        assert (await store.get_active())["agents"]["ops"]["allowed_tools"] == ["read_a"]

    async def test_store_refuses_it_too(self, fresh_policy_table):
        with pytest.raises(ValueError, match="shadow"):
            await PolicyStore().create_version(POLICY, shadow=True, activate=True)

    async def test_staged_shadow_is_stored_but_not_enforced(self, env):
        client, store, _ = env
        r = await _send(
            client, "PUT", "/v1/policy",
            {"policy_data": WIDER, "shadow": True, "activate": False}, key=ADMIN_KEY,
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_shadow"] is True and r.json()["is_active"] is False
        assert (await store.get_active())["agents"]["ops"]["allowed_tools"] == ["read_a"]

    async def test_promotion_clears_the_shadow_flag(self, env):
        client, store, _ = env
        staged = await _send(
            client, "PUT", "/v1/policy",
            {"policy_data": WIDER, "shadow": True, "activate": False}, key=ADMIN_KEY,
        )
        vid = staged.json()["id"]
        r = await _send(client, "POST", f"/v1/policy/rollback/{vid}", None, key=ADMIN_KEY)
        assert r.status_code == 200, r.text
        active = await store.get_active_version()
        assert active.id == vid
        assert active.is_shadow is False

    async def test_repository_refuses_it_below_the_store(self, fresh_policy_table):
        from trust_mediator.db.policy_repo import PolicyRepository

        with pytest.raises(ValueError, match="shadow"):
            await PolicyRepository().create_version(POLICY, shadow=True, activate=True)

    async def test_an_active_version_is_never_reported_as_shadow(self, env):
        """A legacy row stored active+shadow is enforced, so GET says so."""
        client, store, _ = env
        version = await store.get_active_version()
        async with AsyncSessionLocal() as s:
            row = await s.get(PolicyVersionORM, version.id)
            row.is_shadow = True
            await s.commit()
        r = await client.get("/v1/policy", headers={"X-API-Key": DATA_KEY})
        assert r.status_code == 200
        assert r.json()["shadow"] is False
