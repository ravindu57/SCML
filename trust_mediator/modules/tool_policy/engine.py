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
  4. If any argument derives from untrusted data, apply untrusted_arg_policy.
  5. Irreversible / high-impact actions always require approval.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

import structlog

from trust_mediator.models.context_envelope import TrustLabel
from trust_mediator.models.tool_call import (
    PolicyDecision,
    PolicyDecisionCode,
    ToolCallRequest,
)
from trust_mediator.modules.tool_policy.policy_loader import PolicyLoader

logger = structlog.get_logger(__name__)


class RateLimiter:
    """Sliding-window rate limiter (in-memory, per-agent-per-tool)."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        window = self._windows[key]
        # Remove expired entries
        while window and window[0] < now - window_seconds:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True


class PolicyEngine:
    """
    Evaluates ToolCallRequests against the active declarative policy.

    Thread-safety: the rate limiter uses deques (GIL-protected in CPython).
    For multi-process deployments, move rate_limit counters to Redis.
    """

    def __init__(self, loader: PolicyLoader) -> None:
        self._loader = loader
        self._rate_limiter = RateLimiter()

    async def evaluate(self, request: ToolCallRequest) -> PolicyDecision:
        """
        Main authorisation entry point. Returns a PolicyDecision.
        """
        try:
            policy = await self._loader.get_policy()
        except Exception as e:
            logger.error("policy_engine.policy_load_error", error=str(e))
            return PolicyDecision(
                decision=PolicyDecisionCode.MEDIATOR_ERROR,
                reason="Policy store unavailable — fail-closed",
                reason_code=PolicyDecisionCode.MEDIATOR_ERROR,
            )

        agent_policy = (
            policy.get("agents", {}).get(request.agent_id)
            or policy.get("agents", {}).get("default")
            or {}
        )

        # 1. Allow-list check (FR-PE-02)
        # Sentinel: if key is absent → no restriction; if key is present (even []) → explicit list
        _MISSING = object()
        _allowed_tools_raw = agent_policy.get("allowed_tools", _MISSING)
        if _allowed_tools_raw is not _MISSING:
            allowed_tools: list[str] = _allowed_tools_raw  # type: ignore[assignment]
            if request.tool_name not in allowed_tools:
                return self._deny(
                    PolicyDecisionCode.DENY_NOT_ALLOWLISTED,
                    f"Tool '{request.tool_name}' is not on the allow-list for agent '{request.agent_id}'",
                )

        # 2. Schema / argument constraint check (FR-PE-02)
        tool_config: dict[str, Any] = (
            agent_policy.get("tool_configs", {}).get(request.tool_name, {})
        )
        schema_error = self._check_schema(request, tool_config)
        if schema_error:
            return self._deny(PolicyDecisionCode.DENY_SCHEMA_VIOLATION, schema_error)

        value_error = self._check_value_constraints(request, tool_config)
        if value_error:
            return self._deny(PolicyDecisionCode.DENY_VALUE_CONSTRAINT, value_error)

        # 3. Rate limiting (FR-PE-05)
        rate_limits = agent_policy.get("rate_limits", {})
        rpm_limit = rate_limits.get("tool_calls_per_minute", 120)
        rate_key = f"{request.agent_id}:{request.tool_name}"
        if not self._rate_limiter.is_allowed(rate_key, rpm_limit, window_seconds=60):
            return self._deny(
                PolicyDecisionCode.DENY_RATE_LIMIT,
                f"Rate limit ({rpm_limit} calls/min) exceeded for tool '{request.tool_name}'",
            )

        # 4. Untrusted argument policy (FR-PE-04)
        if request.has_untrusted_args:
            untrusted_arg_policy = agent_policy.get("untrusted_arg_policy", "require_approval")
            if untrusted_arg_policy == "deny":
                return self._deny(
                    PolicyDecisionCode.DENY_UNTRUSTED_ARG,
                    "Tool call arguments derive from untrusted data; policy=deny",
                )
            elif untrusted_arg_policy in ("require_approval", "approve"):
                return self._require_approval(
                    PolicyDecisionCode.REQUIRE_APPROVAL_UNTRUSTED_ARG,
                    "Tool call arguments derive from untrusted data; human approval required",
                )

        # 5. Irreversible / high-impact approval gate (FR-PE-03)
        require_approval_for: list[str] = agent_policy.get(
            "require_approval_for", ["irreversible", "high_impact"]
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
        """Check per-argument value constraints (allow-lists, patterns)."""
        constraints: dict[str, Any] = tool_config.get("argument_constraints", {})
        for arg_name, constraint in constraints.items():
            value = request.arguments.get(arg_name)
            if value is None:
                continue
            if "allowed_values" in constraint:
                if str(value) not in [str(v) for v in constraint["allowed_values"]]:
                    return (
                        f"Argument '{arg_name}' value '{value}' not in allowed_values"
                    )
            if "max_length" in constraint:
                if len(str(value)) > constraint["max_length"]:
                    return (
                        f"Argument '{arg_name}' exceeds max_length {constraint['max_length']}"
                    )
            if "pattern" in constraint:
                import re
                if not re.match(constraint["pattern"], str(value)):
                    return f"Argument '{arg_name}' does not match required pattern"
        return None
