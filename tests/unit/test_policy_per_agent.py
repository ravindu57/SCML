"""
FR-CP-01 — per-agent policy updates, so a mediator can serve more than one team.

`PUT /v1/policy` replaces the whole document including the `agents` map. Two
teams administering different agents through it clobber each other: last write
wins, and the loser is not told — their agent falls through to `default`, which
is deny-all, and simply stops working.

That is not hypothetical. Running AgentDojo's four suites required putting all
four agents in a single file for exactly this reason; loading them one at a time
would have left only the last.

The concurrency test is the one that matters. An implementation that reads the
active policy, edits one key and calls `create_version` passes every other test
here and still loses a concurrent update — the window shrinks from permanent to
milliseconds, which is worse, because it then only fails in production.
"""
from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from trust_mediator.api.app import create_app
from trust_mediator.api.dependencies import get_policy_store
from trust_mediator.db.base import Base, engine
from trust_mediator.db.policy_repo import PolicyVersionORM
from trust_mediator.modules.policy_store.store import PolicyStore

BASE_POLICY = {
    "agents": {
        "default": {"allowed_tools": [], "untrusted_arg_policy": "require_approval"},
        "team_a": {"allowed_tools": ["read_a"], "untrusted_arg_policy": "deny"},
        "team_b": {"allowed_tools": ["read_b"], "untrusted_arg_policy": "deny"},
    },
    "memory": {"integrity_score_threshold": 0.65},
}


@pytest.fixture
async def store():
    """Fresh policy table per test.

    Dropping first is not tidiness. `create_all` silently skips a table that
    already exists, and the test database persists between runs — so a schema
    change is tested against the *old* schema and the new constraint appears not
    to work. That cost three debugging rounds on the concurrency tests here:
    the optimistic-concurrency column existed in the model and not in the file
    on disk. Only this table is dropped, so nothing else in the suite is
    disturbed.
    """
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    s = PolicyStore()
    await s.create_version(BASE_POLICY, description="base", created_by="test")
    yield s


@pytest.fixture
async def client(store):
    app = create_app()
    app.dependency_overrides[get_policy_store] = lambda: store
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c
    app.dependency_overrides.clear()


class TestIsolationBetweenAgents:
    async def test_updating_one_agent_leaves_the_others(self, store):
        await store.upsert_agent("team_a", {"allowed_tools": ["read_a", "write_a"]})
        policy = await store.get_active()
        assert policy["agents"]["team_a"]["allowed_tools"] == ["read_a", "write_a"]
        assert policy["agents"]["team_b"]["allowed_tools"] == ["read_b"], (
            "team_b was clobbered by an update to team_a"
        )
        assert "default" in policy["agents"]

    async def test_non_agent_sections_survive(self, store):
        await store.upsert_agent("team_a", {"allowed_tools": []})
        policy = await store.get_active()
        assert policy["memory"]["integrity_score_threshold"] == 0.65

    async def test_a_new_agent_can_be_added(self, store):
        await store.upsert_agent("team_c", {"allowed_tools": ["read_c"]})
        agents = (await store.get_active())["agents"]
        assert set(agents) == {"default", "team_a", "team_b", "team_c"}

    async def test_each_change_is_a_new_version(self, store):
        before = (await store.get_active_version()).version_number
        await store.upsert_agent("team_a", {"allowed_tools": ["x"]})
        after = (await store.get_active_version()).version_number
        assert after == before + 1, "a policy change must be auditable as a version"


class TestConcurrentUpdates:
    """The reason this lives in the repository inside one locked transaction."""

    async def test_two_teams_updating_different_agents_do_not_clobber(self, store):
        await asyncio.gather(
            store.upsert_agent("team_a", {"allowed_tools": ["a1", "a2"]}),
            store.upsert_agent("team_b", {"allowed_tools": ["b1", "b2"]}),
        )
        agents = (await store.get_active())["agents"]
        assert agents["team_a"]["allowed_tools"] == ["a1", "a2"], "team_a's write was lost"
        assert agents["team_b"]["allowed_tools"] == ["b1", "b2"], "team_b's write was lost"

    async def test_many_concurrent_updates_all_survive(self, store):
        await asyncio.gather(
            *(store.upsert_agent(f"agent_{i}", {"allowed_tools": [f"t{i}"]})
              for i in range(8))
        )
        agents = (await store.get_active())["agents"]
        for i in range(8):
            assert agents[f"agent_{i}"]["allowed_tools"] == [f"t{i}"], f"agent_{i} lost"


class TestDefaultAgentIsProtected:
    async def test_default_cannot_be_upserted(self, store):
        """`default` is the deny-all fallback for every unconfigured agent, so
        widening it through a per-agent call grants authority to agents nobody
        has configured yet."""
        with pytest.raises(ValueError, match="default"):
            await store.upsert_agent("default", {"allowed_tools": ["everything"]})

    async def test_default_cannot_be_deleted(self, store):
        with pytest.raises(ValueError, match="default"):
            await store.delete_agent("default")

    async def test_default_survives_other_edits(self, store):
        await store.upsert_agent("team_a", {"allowed_tools": ["x"]})
        assert (await store.get_active())["agents"]["default"]["allowed_tools"] == []


class TestDeletion:
    async def test_deleting_an_agent_drops_it_to_deny_all(self, store):
        await store.delete_agent("team_a")
        agents = (await store.get_active())["agents"]
        assert "team_a" not in agents
        assert "team_b" in agents, "deleting team_a removed team_b"


class TestValidation:
    async def test_missing_allowed_tools_is_rejected(self, store):
        """Absent means 'no tool restriction' to the engine (engine.py:79-83),
        while [] means 'deny everything'. A typo is the difference between a
        locked-down agent and an unrestricted one, silently."""
        with pytest.raises(ValueError, match="allowed_tools"):
            await store.upsert_agent("team_a", {"untrusted_arg_policy": "deny"})

    async def test_an_unrecognised_untrusted_arg_policy_is_rejected(self, store):
        """The engine matches 'deny' and 'require_approval'/'approve' and falls
        through to allow, so 'denied' would permit every tainted argument."""
        with pytest.raises(ValueError, match="untrusted_arg_policy"):
            await store.upsert_agent(
                "team_a", {"allowed_tools": [], "untrusted_arg_policy": "denied"}
            )

    async def test_an_unrecognised_approval_trigger_is_rejected(self, store):
        with pytest.raises(ValueError, match="require_approval_for"):
            await store.upsert_agent(
                "team_a", {"allowed_tools": [], "require_approval_for": ["irreversable"]}
            )

    async def test_a_valid_agent_passes(self, store):
        await store.upsert_agent(
            "team_a",
            {
                "allowed_tools": ["read_a"],
                "untrusted_arg_policy": "deny",
                "require_approval_for": ["irreversible", "high_impact"],
            },
        )


@pytest.mark.asyncio
class TestRoutes:
    async def test_get_put_delete_round_trip(self, client):
        r = await client.get("/v1/policy/agents/team_a")
        assert r.status_code == 200
        assert r.json()["policy"]["allowed_tools"] == ["read_a"]

        r = await client.put(
            "/v1/policy/agents/team_a",
            json={"agent_policy": {"allowed_tools": ["read_a", "write_a"]}},
        )
        assert r.status_code == 200, r.text

        r = await client.get("/v1/policy/agents/team_a")
        assert r.json()["policy"]["allowed_tools"] == ["read_a", "write_a"]

        assert (await client.delete("/v1/policy/agents/team_a")).status_code == 200
        assert (await client.get("/v1/policy/agents/team_a")).status_code == 404

    async def test_unknown_agent_is_404_not_empty(self, client):
        """A 404 says 'this agent falls back to deny-all', which is materially
        different from an agent configured to allow nothing."""
        r = await client.get("/v1/policy/agents/nobody")
        assert r.status_code == 404
        assert "deny-all" in r.json()["detail"]

    async def test_invalid_agent_policy_is_422(self, client):
        r = await client.put(
            "/v1/policy/agents/team_a", json={"agent_policy": {"no_allowed_tools": 1}}
        )
        assert r.status_code == 422
        assert "allowed_tools" in r.json()["detail"]

    async def test_the_default_agent_is_refused_over_http(self, client):
        r = await client.put(
            "/v1/policy/agents/default", json={"agent_policy": {"allowed_tools": ["*"]}}
        )
        assert r.status_code == 422

    async def test_the_version_records_the_authenticated_principal(self, client):
        """A policy change is an administrative action; the history should say
        who made it rather than what they typed into a field."""
        r = await client.put(
            "/v1/policy/agents/team_b", json={"agent_policy": {"allowed_tools": []}}
        )
        assert r.status_code == 200
        assert r.json()["created_by"] == "anonymous"  # dev mode principal
