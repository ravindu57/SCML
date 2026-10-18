"""
Policy fail-closed tests (FR-PE-01, FR-PE-02, FR-PE-03, FR-PE-04; PRD §5.2, §9).

A malformed or incomplete policy document must never widen authority. Before
these tests, `PUT /v1/policy` checked only that `agents` and `memory` keys
existed, and the engine read an absent `allowed_tools` as "no restriction" —
so `{"agents": {}, "memory": {}}` authorised every tool for every agent. Two
layers now refuse that independently:

- the validator rejects the document before it is stored, and
- the engine denies on any policy shape it does not recognise, so a document
  stored before validation tightened (or reaching it by another path) still
  fails closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from trust_mediator.models.context_envelope import TrustLabel
from trust_mediator.models.tool_call import PolicyDecisionCode, ToolCallRequest
from trust_mediator.modules.policy_store.store import PolicyStore
from trust_mediator.modules.tool_policy.engine import PolicyEngine
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader

REPO = Path(__file__).resolve().parents[2]

_WELL_FORMED_AGENT = {
    "allowed_tools": ["web_search", "send_email"],
    "require_approval_for": ["irreversible", "high_impact"],
    "untrusted_arg_policy": "require_approval",
    "rate_limits": {"tool_calls_per_minute": 1000},
}


def _engine(policy: dict) -> PolicyEngine:
    loader = PolicyLoader(policy_repo=None, default_path=None)
    loader._memory_cache = {"default": policy}
    loader._cache_loaded_at = {"default": 1e20}
    return PolicyEngine(loader)


def _request(tool: str, agent_id: str = "default", untrusted: bool = False) -> ToolCallRequest:
    return ToolCallRequest(
        session_id="s",
        tool_name=tool,
        arguments={"q": "x"},
        argument_trust_labels={"q": TrustLabel.UNTRUSTED_DATA} if untrusted else {},
        agent_id=agent_id,
    )


def _with_default(**overrides) -> dict:
    return {"agents": {"default": {**_WELL_FORMED_AGENT, **overrides}}, "memory": {}}


@pytest.mark.asyncio
class TestEngineFailsClosedOnMalformedPolicy:
    async def test_fr_pe_01_empty_agents_map_denies_every_tool(self):
        decision = await _engine({"agents": {}, "memory": {}}).evaluate(_request("anything"))
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_fr_pe_01_agent_without_allowed_tools_is_denied(self):
        policy = {"agents": {"default": {"untrusted_arg_policy": "deny"}}, "memory": {}}
        decision = await _engine(policy).evaluate(_request("web_search"))
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_fr_pe_01_agents_not_a_mapping_is_denied(self):
        decision = await _engine({"agents": ["default"], "memory": {}}).evaluate(
            _request("web_search")
        )
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_fr_pe_02_string_allow_list_is_not_a_substring_match(self):
        # `"send" in "send_email"` is True for a str; it must not authorise.
        engine = _engine(_with_default(allowed_tools="send_email"))
        for tool in ("send", "send_email"):
            decision = await engine.evaluate(_request(tool))
            assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED, tool

    async def test_fr_pe_02_null_allow_list_denies_instead_of_raising(self):
        decision = await _engine(_with_default(allowed_tools=None)).evaluate(_request("web_search"))
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_fr_pe_04_untrusted_arg_policy_allow_does_not_authorise(self):
        """§5.2: untrusted data may never authorise a tool call, by config or otherwise."""
        decision = await _engine(_with_default(untrusted_arg_policy="allow")).evaluate(
            _request("web_search", untrusted=True)
        )
        assert decision.decision == PolicyDecisionCode.DENY_UNTRUSTED_ARG

    async def test_fr_pe_04_misspelled_untrusted_arg_policy_denies(self):
        decision = await _engine(_with_default(untrusted_arg_policy="denied")).evaluate(
            _request("web_search", untrusted=True)
        )
        assert decision.decision == PolicyDecisionCode.DENY_UNTRUSTED_ARG

    async def test_fr_pe_05_non_integer_rate_limit_denies_instead_of_raising(self):
        policy = _with_default(rate_limits={"tool_calls_per_minute": "10"})
        decision = await _engine(policy).evaluate(_request("web_search"))
        assert decision.decision == PolicyDecisionCode.DENY_RATE_LIMIT

    async def test_fr_pe_03_tool_named_in_require_approval_for_needs_approval(self):
        """The shipped policies list `send_email` / `initiate_transfer` here;
        the engine used to ignore tool names and allow them outright."""
        decision = await _engine(
            _with_default(require_approval_for=["irreversible", "send_email"])
        ).evaluate(_request("send_email"))
        assert decision.decision == PolicyDecisionCode.REQUIRE_APPROVAL
        assert decision.requires_approval

    async def test_fr_pe_03_require_approval_for_not_a_list_denies(self):
        decision = await _engine(_with_default(require_approval_for="send_email")).evaluate(
            _request("web_search")
        )
        assert not decision.is_allowed

    @pytest.mark.parametrize(
        "constraint",
        [
            "pattern",                      # not a dict: was a substring test, then a TypeError
            {"max_length": "10"},           # str vs int comparison raised
            {"allowed_values": 5},          # not iterable, raised
            {"allowed_values": "evil.com"}, # str became a per-character allow-list
            {"pattern": 7},
        ],
        ids=["constraint-str", "max_length-str", "allowed_values-int", "allowed_values-str", "pattern-int"],
    )
    async def test_fr_pe_02_malformed_constraint_denies_instead_of_raising(self, constraint):
        policy = _with_default(
            tool_configs={"web_search": {"argument_constraints": {"q": constraint}}}
        )
        decision = await _engine(policy).evaluate(
            ToolCallRequest(session_id="s", tool_name="web_search", arguments={"q": "e"})
        )
        assert decision.decision == PolicyDecisionCode.DENY_VALUE_CONSTRAINT

    async def test_fr_pe_02_tool_configs_not_a_mapping_denies(self):
        decision = await _engine(_with_default(tool_configs=[])).evaluate(_request("web_search"))
        assert not decision.is_allowed

    async def test_fr_pe_02_pattern_must_match_the_whole_value(self):
        policy = _with_default(
            tool_configs={"web_search": {"argument_constraints": {"q": {"pattern": "^[a-z]+"}}}}
        )
        decision = await _engine(policy).evaluate(
            ToolCallRequest(session_id="s", tool_name="web_search", arguments={"q": "abc;rm -rf"})
        )
        assert decision.decision == PolicyDecisionCode.DENY_VALUE_CONSTRAINT

    @pytest.mark.parametrize("entry", [{}, None, []], ids=["empty-dict", "null", "list"])
    async def test_fr_pe_01_empty_agent_entry_does_not_inherit_default(self, entry):
        """A configured-but-empty agent must deny, not borrow `default`'s authority."""
        policy = {"agents": {"default": _WELL_FORMED_AGENT, "ops": entry}, "memory": {}}
        decision = await _engine(policy).evaluate(_request("web_search", agent_id="ops"))
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_section_9_engine_error_is_a_mediator_error_not_an_exception(self):
        """An exception would become an unaudited 500, which fail-open clients
        read as permission. The engine returns a decision instead."""

        class _BrokenLimiter:
            async def is_allowed(self, *a, **k):
                raise ConnectionError("redis down")

        loader = PolicyLoader(policy_repo=None, default_path=None)
        loader._memory_cache = {"default": _with_default()}
        loader._cache_loaded_at = {"default": 1e20}
        decision = await PolicyEngine(loader, rate_limiter=_BrokenLimiter()).evaluate(
            _request("web_search")
        )
        assert decision.decision == PolicyDecisionCode.MEDIATOR_ERROR
        assert not decision.is_allowed

    async def test_well_formed_policy_still_allows(self):
        decision = await _engine(_with_default()).evaluate(_request("web_search"))
        assert decision.decision == PolicyDecisionCode.ALLOW


class TestDocumentValidation:
    def test_fr_pe_01_document_without_default_agent_is_rejected(self):
        errors = PolicyStore._validate({"agents": {}, "memory": {}})
        assert any("default" in e for e in errors)

    def test_fr_pe_01_every_agent_in_a_document_is_validated(self):
        doc = {
            "agents": {"default": _WELL_FORMED_AGENT, "loose": {"untrusted_arg_policy": "deny"}},
            "memory": {},
        }
        errors = PolicyStore._validate(doc)
        assert any("loose" in e and "allowed_tools" in e for e in errors)

    def test_fr_pe_04_untrusted_arg_policy_allow_is_rejected(self):
        errors = PolicyStore._validate_agent({**_WELL_FORMED_AGENT, "untrusted_arg_policy": "allow"})
        assert any("untrusted_arg_policy" in e for e in errors)

    def test_fr_pe_02_allowed_tools_entries_must_be_strings(self):
        errors = PolicyStore._validate_agent({**_WELL_FORMED_AGENT, "allowed_tools": ["ok", 3]})
        assert any("allowed_tools" in e for e in errors)

    def test_fr_pe_03_require_approval_for_accepts_an_allow_listed_tool(self):
        agent = {**_WELL_FORMED_AGENT, "require_approval_for": ["irreversible", "send_email"]}
        assert PolicyStore._validate_agent(agent) == []

    def test_fr_pe_03_require_approval_for_rejects_an_unknown_entry(self):
        # Neither a category nor a tool this agent may call: almost certainly a
        # typo, and an approval gate on it would never fire.
        agent = {**_WELL_FORMED_AGENT, "require_approval_for": ["irreversable"]}
        errors = PolicyStore._validate_agent(agent)
        assert any("require_approval_for" in e for e in errors)

    def test_fr_pe_05_rate_limit_must_be_a_positive_integer(self):
        for bad in ("10", 0, -1, True, 1.5):
            agent = {**_WELL_FORMED_AGENT, "rate_limits": {"tool_calls_per_minute": bad}}
            assert any("tool_calls_per_minute" in e for e in PolicyStore._validate_agent(agent)), bad

    def test_fr_pe_02_uncompilable_argument_pattern_is_rejected(self):
        agent = {
            **_WELL_FORMED_AGENT,
            "tool_configs": {"web_search": {"argument_constraints": {"q": {"pattern": "(["}}}},
        }
        errors = PolicyStore._validate_agent(agent)
        assert any("pattern" in e for e in errors)

    @pytest.mark.parametrize(
        "bad",
        [
            {"untrusted_arg_policy": ["deny"]},
            {"require_approval_for": [{"a": 1}]},
        ],
        ids=["uap-list", "raf-dict-entry"],
    )
    def test_unhashable_values_are_reported_not_raised(self, bad):
        assert PolicyStore._validate_agent({**_WELL_FORMED_AGENT, **bad})

    @pytest.mark.parametrize(
        "constraint",
        ["pattern", {"max_length": "10"}, {"allowed_values": "evil.com"}, {"patern": "x"}],
        ids=["not-a-dict", "max_length-str", "allowed_values-str", "unknown-key"],
    )
    def test_fr_pe_02_malformed_constraints_are_rejected(self, constraint):
        agent = {
            **_WELL_FORMED_AGENT,
            "tool_configs": {"web_search": {"argument_constraints": {"q": constraint}}},
        }
        assert PolicyStore._validate_agent(agent)

    @pytest.mark.parametrize(
        "tool_config",
        [
            {"argument_shema": {"type": "object"}},     # typo would silently drop the schema
            {"argument_schema": "object"},
            {"argument_schema": {"type": "not-a-type"}},
            {"argument_constraints": {"q": {"pattern": "a{99999999999}"}}},  # OverflowError
        ],
        ids=["schema-typo", "schema-str", "schema-invalid", "pattern-overflow"],
    )
    def test_fr_pe_02_malformed_tool_config_is_reported_not_raised(self, tool_config):
        agent = {**_WELL_FORMED_AGENT, "tool_configs": {"web_search": tool_config}}
        assert PolicyStore._validate_agent(agent)

    @pytest.mark.parametrize(
        "path",
        sorted(
            [
                *REPO.glob("policies/*.yaml"),
                *REPO.glob("benchmarks/testbeds/agentdojo/policies/*.yaml"),
                REPO / "demo-agent/policies/policy.json",
                REPO / "orchestrator/policies/policy.json",
            ]
        ),
        ids=lambda p: f"{p.parent.parent.name}/{p.name}",
    )
    def test_every_shipped_policy_validates(self, path):
        """Tightening validation must not lock out a policy the project ships."""
        assert PolicyStore._validate(yaml.safe_load(path.read_text())) == []


@pytest.mark.asyncio
class TestLoaderFallback:
    async def test_fr_pe_01_invalid_default_yaml_falls_back_to_deny_all(self, tmp_path):
        bad = tmp_path / "policy.yaml"
        bad.write_text(yaml.safe_dump({"agents": {}, "memory": {}}))
        engine = PolicyEngine(PolicyLoader(policy_repo=None, default_path=bad))
        decision = await engine.evaluate(_request("anything"))
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED


@pytest.fixture
async def fresh_policy_table():
    """A clean policy_versions table per test (mirrors test_tenant_policy)."""
    from trust_mediator.db.base import Base, engine
    from trust_mediator.db.policy_repo import PolicyVersionORM

    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(PolicyVersionORM.__table__.drop, checkfirst=True)
        await conn.run_sync(Base.metadata.create_all)


@pytest.mark.asyncio
class TestRollbackRevalidates:
    async def test_fr_cp_01_rollback_refuses_a_version_stored_under_laxer_rules(
        self, fresh_policy_table
    ):
        """Versions written before validation tightened (here written straight
        through the repository, as the old `_validate` allowed) must not come
        back into force through rollback."""
        store = PolicyStore()
        legacy = await store._repo.create_version(
            policy_data={"agents": {}, "memory": {}},
            description="legacy allow-everything",
            created_by="test",
            activate=True,
        )
        good = await store.create_version(_with_default(), description="current")

        with pytest.raises(ValueError, match="invalid policy version"):
            await store.rollback(legacy.id)
        assert (await store.get_active_version()).id == good.id

    async def test_fr_cp_01_rollback_to_a_valid_version_still_works(self, fresh_policy_table):
        store = PolicyStore()
        v1 = await store.create_version(_with_default(), description="v1")
        await store.create_version(_with_default(allowed_tools=["web_search"]), description="v2")
        assert await store.rollback(v1.id) is True
        assert (await store.get_active_version()).id == v1.id
