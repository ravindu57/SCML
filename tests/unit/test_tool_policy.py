"""Unit tests for the Tool-Call Policy Engine (§6.4)."""
import pytest

from trust_mediator.models.context_envelope import TrustLabel
from trust_mediator.models.tool_call import PolicyDecisionCode, ToolCallRequest
from trust_mediator.modules.tool_policy.engine import PolicyEngine
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader


SAMPLE_POLICY = {
    "agents": {
        "default": {
            "allowed_tools": ["web_search", "summarise"],
            "require_approval_for": ["irreversible", "high_impact"],
            "untrusted_arg_policy": "require_approval",
            "rate_limits": {"tool_calls_per_minute": 1000},
        }
    },
    "memory": {"integrity_score_threshold": 0.65},
    "scanner": {},
    "redaction": {},
}


def make_loader() -> PolicyLoader:
    """
    A loader pre-warmed with SAMPLE_POLICY, built through the real constructor.

    Overriding only the cache rather than hand-assembling every attribute via
    __new__: the hand-assembled form silently stops matching the moment the
    loader gains a field, and the resulting AttributeError surfaces as whatever
    the caller's error handling turns it into rather than as a failure here.
    """
    loader = PolicyLoader(policy_repo=None, default_path=None)
    loader._memory_cache = SAMPLE_POLICY
    loader._cache_loaded_at = 1e20  # Far future — always fresh
    return loader


def make_request(tool_name: str, agent_id: str = "default", **kwargs) -> ToolCallRequest:
    return ToolCallRequest(
        session_id="test-session",
        tool_name=tool_name,
        arguments=kwargs.get("arguments", {}),
        argument_trust_labels=kwargs.get("argument_trust_labels", {}),
        agent_id=agent_id,
        is_irreversible=kwargs.get("is_irreversible", False),
        is_high_impact=kwargs.get("is_high_impact", False),
    )


@pytest.mark.asyncio
class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine(make_loader())

    async def test_allowed_tool_passes(self):
        req = make_request("web_search")
        decision = await self.engine.evaluate(req)
        assert decision.decision == PolicyDecisionCode.ALLOW

    async def test_not_allowlisted_denied(self):
        req = make_request("send_email")
        decision = await self.engine.evaluate(req)
        assert decision.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED

    async def test_irreversible_requires_approval(self):
        req = make_request("web_search", is_irreversible=True)
        decision = await self.engine.evaluate(req)
        assert decision.decision == PolicyDecisionCode.REQUIRE_APPROVAL
        assert decision.approver_required is True
        assert decision.approval_id is not None

    async def test_high_impact_requires_approval(self):
        req = make_request("web_search", is_high_impact=True)
        decision = await self.engine.evaluate(req)
        assert "approval" in decision.decision.value

    async def test_untrusted_arg_requires_approval(self):
        req = make_request(
            "web_search",
            argument_trust_labels={"query": TrustLabel.UNTRUSTED_DATA},
        )
        decision = await self.engine.evaluate(req)
        assert "approval" in decision.decision.value or decision.decision == PolicyDecisionCode.DENY_UNTRUSTED_ARG

    async def test_rate_limiting(self):
        """After limit exhaustion, should deny with rate-limit code."""
        policy = {
            "agents": {
                "default": {
                    "allowed_tools": ["fast_tool"],
                    "require_approval_for": [],
                    "untrusted_arg_policy": "allow",
                    "rate_limits": {"tool_calls_per_minute": 2},
                }
            },
            "memory": {"integrity_score_threshold": 0.65},
        }
        loader = make_loader()
        loader._memory_cache = policy
        engine = PolicyEngine(loader)

        for _ in range(2):
            d = await engine.evaluate(make_request("fast_tool"))
            assert d.decision == PolicyDecisionCode.ALLOW

        # Third call should be rate-limited
        d = await engine.evaluate(make_request("fast_tool"))
        assert d.decision == PolicyDecisionCode.DENY_RATE_LIMIT

    async def test_empty_allowlist_denies_all(self):
        """Empty allowed_tools → all tools denied."""
        policy = {
            "agents": {"default": {"allowed_tools": [], "require_approval_for": [], "untrusted_arg_policy": "allow", "rate_limits": {}}},
            "memory": {},
        }
        loader = make_loader()
        loader._memory_cache = policy
        engine = PolicyEngine(loader)
        d = await engine.evaluate(make_request("any_tool"))
        assert d.decision == PolicyDecisionCode.DENY_NOT_ALLOWLISTED
