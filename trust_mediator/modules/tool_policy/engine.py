"""
§6.4 — Tool-Call Policy Engine.

Authorises every proposed tool invocation against declarative least-agency
policy before execution (FR-PE-01 through FR-PE-05).

Decisions:
  allow              — proceed
  deny.*             — blocked; agent must not call the tool
  require_approval   — gated; a human must confirm before execution

Key rules:
  1. Tool must be on the agent's allow-list (deny if not).
  2. Arguments must conform to the tool's declared schema.
  3. Rate/quota limits must not be exceeded.
  4. If any argument derives from untrusted data, apply untrusted_arg_policy
     (approval or denial — never allow, §5.2).
  5. Irreversible / high-impact actions, and tools named in
     require_approval_for, require approval.

Any policy shape the engine does not recognise denies (§9 fail-closed);
validation.py rejects the same shapes before they are stored.
"""

from __future__ import annotations

from typing import Any

import structlog

from trust_mediator.config import settings
from trust_mediator.models.tool_call import (
    PolicyDecision,
    PolicyDecisionCode,
    ToolCallRequest,
)
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader
from trust_mediator.modules.tool_policy.rate_limiter import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    build_rate_limiter,
)

logger = structlog.get_logger(__name__)


class PolicyEngine:
    """
    Evaluates ToolCallRequests against the active declarative policy.

    Rate limiting is Redis-backed when REDIS_URL is set (required for
    multi-worker / gateway deployments); otherwise per-process in-memory.
    """

    def __init__(
        self,
        loader: PolicyLoader,
        rate_limiter: InMemoryRateLimiter | RedisRateLimiter | None = None,
    ) -> None:
        self._loader = loader
        self._rate_limiter = rate_limiter or build_rate_limiter(settings.redis_url)

    async def evaluate(self, request: ToolCallRequest) -> PolicyDecision:
        """
        Main authorisation entry point. Returns a PolicyDecision; never raises.

        An exception escaping here would surface as an HTTP 500 with no
        TOOL_POLICY audit event, and a fail-open client reads a 500 as
        permission. Any unexpected error is therefore a MEDIATOR_ERROR
        decision, which the pipeline audits like every other (§9, FR-AL-01).
        """
        try:
            return await self._evaluate(request)
        except Exception as e:  # noqa: BLE001 — fail-closed boundary
            logger.error(
                "policy_engine.evaluate_error",
                error_type=type(e).__name__,
                exc_info=True,  # local logs only; never a span attribute
                tool=request.tool_name,
                agent=request.agent_id,
            )
            return PolicyDecision(
                decision=PolicyDecisionCode.MEDIATOR_ERROR,
                reason="Policy evaluation failed — fail-closed",
                reason_code=PolicyDecisionCode.MEDIATOR_ERROR,
            )

    async def _evaluate(self, request: ToolCallRequest) -> PolicyDecision:
        """
        The checks behind ``evaluate``.

        Policy is resolved **per tenant**: ``request.tenant_id`` selects the
        caller's policy document, so two companies with the same ``agent_id``
        are authorised against their own document and never each other's.
        """
        try:
            policy = await self._loader.get_policy(request.tenant_id)
        except Exception as e:
            logger.error("policy_engine.policy_load_error", error=str(e))
            return PolicyDecision(
                decision=PolicyDecisionCode.MEDIATOR_ERROR,
                reason="Policy store unavailable — fail-closed",
                reason_code=PolicyDecisionCode.MEDIATOR_ERROR,
            )

        agent_policy = self._resolve_agent_policy(policy, request.agent_id)

        # 1. Allow-list check (FR-PE-01/02). Fail closed on anything but a list
        # of names. An absent key used to mean "no restriction", so an empty
        # or partial document authorised every tool; a string made `in` a
        # substring test ("send" in "send_email").
        allowed_tools = agent_policy.get("allowed_tools")
        if not isinstance(allowed_tools, list):
            return self._deny(
                PolicyDecisionCode.DENY_NOT_ALLOWLISTED,
                f"No valid allow-list for agent '{request.agent_id}' — fail-closed",
            )
        if request.tool_name not in allowed_tools:
            return self._deny(
                PolicyDecisionCode.DENY_NOT_ALLOWLISTED,
                f"Tool '{request.tool_name}' is not on the allow-list for agent '{request.agent_id}'",
            )

        # 2. Schema / argument constraint check (FR-PE-02)
        tool_configs = agent_policy.get("tool_configs", {})
        tool_config = tool_configs.get(request.tool_name, {}) if isinstance(tool_configs, dict) else None
        if not isinstance(tool_config, dict):
            return self._deny(
                PolicyDecisionCode.DENY_SCHEMA_VIOLATION,
                f"Malformed tool_configs for agent '{request.agent_id}' — fail-closed",
            )
        schema_error = self._check_schema(request, tool_config)
        if schema_error:
            return self._deny(PolicyDecisionCode.DENY_SCHEMA_VIOLATION, schema_error)

        value_error = self._check_value_constraints(request, tool_config)
        if value_error:
            return self._deny(PolicyDecisionCode.DENY_VALUE_CONSTRAINT, value_error)

        # 3. Rate limiting (FR-PE-05). A malformed limit denies rather than
        # raising: an exception here surfaces as a 500, which a fail-open
        # client would read as permission.
        rate_limits = agent_policy.get("rate_limits", {})
        rpm_limit = (
            rate_limits.get("tool_calls_per_minute", settings.policy_default_tool_calls_per_minute)
            if isinstance(rate_limits, dict)
            else None
        )
        if not isinstance(rpm_limit, int) or isinstance(rpm_limit, bool) or rpm_limit <= 0:
            return self._deny(
                PolicyDecisionCode.DENY_RATE_LIMIT,
                f"Malformed rate limit for agent '{request.agent_id}' — fail-closed",
            )
        # Tenant first (Sec #12): agent ids are per tenant, so two companies'
        # "ops" agents must not share, and exhaust, one bucket.
        rate_key = f"{request.tenant_id}:{request.agent_id}:{request.tool_name}"
        if not await self._rate_limiter.is_allowed(rate_key, rpm_limit, window_seconds=60):
            return self._deny(
                PolicyDecisionCode.DENY_RATE_LIMIT,
                f"Rate limit ({rpm_limit} calls/min) exceeded for tool '{request.tool_name}'",
            )

        # 4. Untrusted argument policy (FR-PE-04, §5.2). Untrusted data never
        # authorises a call: anything other than an approval gate denies,
        # including the formerly accepted "allow" and any misspelling.
        if request.has_untrusted_args:
            untrusted_arg_policy = agent_policy.get("untrusted_arg_policy", "require_approval")
            if untrusted_arg_policy in ("require_approval", "approve"):
                return self._require_approval(
                    PolicyDecisionCode.REQUIRE_APPROVAL_UNTRUSTED_ARG,
                    "Tool call arguments derive from untrusted data; human approval required",
                )
            return self._deny(
                PolicyDecisionCode.DENY_UNTRUSTED_ARG,
                f"Tool call arguments derive from untrusted data; policy={untrusted_arg_policy!r}",
            )

        # 5. Approval gate (FR-PE-03). Entries are either a category matched
        # against the caller's hints or a tool name, which gates that tool
        # regardless of hints — the shipped policies list `send_email` and
        # `initiate_transfer` here, and those used to be silently ignored.
        require_approval_for = agent_policy.get(
            "require_approval_for", ["irreversible", "high_impact"]
        )
        if not isinstance(require_approval_for, list):
            return self._deny(
                PolicyDecisionCode.DENY_POLICY_NOT_LOADED,
                f"Malformed 'require_approval_for' for agent '{request.agent_id}' — fail-closed",
            )
        if request.tool_name in require_approval_for:
            return self._require_approval(
                PolicyDecisionCode.REQUIRE_APPROVAL,
                f"Tool '{request.tool_name}' requires human approval by policy",
            )
        if request.is_irreversible and "irreversible" in require_approval_for:
            return self._require_approval(
                PolicyDecisionCode.REQUIRE_APPROVAL_IRREVERSIBLE,
                f"Tool '{request.tool_name}' is marked irreversible; human approval required",
            )
        if request.is_high_impact and "high_impact" in require_approval_for:
            return self._require_approval(
                PolicyDecisionCode.REQUIRE_APPROVAL_HIGH_IMPACT,
                f"Tool '{request.tool_name}' is marked high_impact; human approval required",
            )

        # All checks passed
        decision = PolicyDecision(
            decision=PolicyDecisionCode.ALLOW,
            reason=f"Tool '{request.tool_name}' authorised by policy for agent '{request.agent_id}'",
            reason_code=PolicyDecisionCode.ALLOW,
        )
        logger.info(
            "policy_engine.allow",
            tool=request.tool_name,
            agent=request.agent_id,
            session=request.session_id,
        )
        return decision

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_agent_policy(policy: Any, agent_id: str) -> dict[str, Any]:
        """The agent's entry, else the tenant's `default`, else `{}` (deny)."""
        agents = policy.get("agents") if isinstance(policy, dict) else None
        if not isinstance(agents, dict):
            return {}
        # Key presence, not truthiness: a configured-but-empty entry (`{}`,
        # null, []) must deny, not silently inherit `default`'s authority.
        entry = agents[agent_id] if agent_id in agents else agents.get("default")
        return entry if isinstance(entry, dict) else {}

    def _deny(self, code: PolicyDecisionCode, reason: str) -> PolicyDecision:
        logger.warning("policy_engine.deny", reason_code=code, reason=reason)
        return PolicyDecision(decision=code, reason=reason, reason_code=code)

    def _require_approval(self, code: PolicyDecisionCode, reason: str) -> PolicyDecision:
        import uuid
        approval_id = str(uuid.uuid4())
        logger.info(
            "policy_engine.require_approval",
            reason_code=code,
            approval_id=approval_id,
        )
        return PolicyDecision(
            decision=PolicyDecisionCode.REQUIRE_APPROVAL,
            reason=reason,
            reason_code=code,
            approver_required=True,
            approval_id=approval_id,
        )

    def _check_schema(
        self, request: ToolCallRequest, tool_config: dict[str, Any]
    ) -> str | None:
        """Validate arguments against the declared JSON schema (if any)."""
        schema = tool_config.get("argument_schema")
        if not schema:
            return None
        try:
            import jsonschema
            jsonschema.validate(instance=request.arguments, schema=schema)
        except Exception as e:
            return f"Argument schema violation: {e}"
        return None

    def _check_value_constraints(
        self, request: ToolCallRequest, tool_config: dict[str, Any]
    ) -> str | None:
        """Check per-argument value constraints (allow-lists, patterns).

        Every constraint shape is type-checked and a wrong shape is a denial:
        a string `allowed_values` used to become a per-character allow-list,
        and a string `max_length` raised mid-evaluation.
        """
        constraints = tool_config.get("argument_constraints", {})
        if not isinstance(constraints, dict):
            return "Malformed argument_constraints — fail-closed"
        for arg_name, constraint in constraints.items():
            if not isinstance(constraint, dict):
                return f"Malformed constraint for argument '{arg_name}' — fail-closed"
            value = request.arguments.get(arg_name)
            if value is None:
                continue
            if "allowed_values" in constraint:
                allowed_values = constraint["allowed_values"]
                if not isinstance(allowed_values, list):
                    return f"Malformed allowed_values for argument '{arg_name}' — fail-closed"
                if str(value) not in [str(v) for v in allowed_values]:
                    return (
                        f"Argument '{arg_name}' value '{value}' not in allowed_values"
                    )
            if "max_length" in constraint:
                max_length = constraint["max_length"]
                if not isinstance(max_length, int) or isinstance(max_length, bool):
                    return f"Malformed max_length for argument '{arg_name}' — fail-closed"
                if len(str(value)) > max_length:
                    return (
                        f"Argument '{arg_name}' exceeds max_length {max_length}"
                    )
            if "pattern" in constraint:
                import re
                pattern = constraint["pattern"]
                if not isinstance(pattern, str):
                    return f"Malformed pattern for argument '{arg_name}' — fail-closed"
                # fullmatch: `re.match` anchors only the start, so `^[a-z]+`
                # accepted "abc;rm -rf".
                if not re.fullmatch(pattern, str(value)):
                    return f"Argument '{arg_name}' does not match required pattern"
        return None
