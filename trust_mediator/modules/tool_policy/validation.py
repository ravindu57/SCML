"""
§6.4 / §6.8 — Policy document validation (FR-PE-01..05, PRD §5.2, §9).

One implementation, shared by the control plane (``PolicyStore``, before a
document is stored) and the data plane (``PolicyLoader``, before the gateway
YAML is served). Dependency-free on purpose, so the loader can use it without
importing the database layer.

The rule throughout: a shape the engine does not recognise must be an error
here, because the engine treats it as a denial (see ``engine.py``). Validation
is the place an operator learns about a mistake; the engine is the backstop
that keeps the mistake from widening authority if it gets through anyway.
"""

from __future__ import annotations

import re
from typing import Any

#: `untrusted_arg_policy` values the engine branches on. There is deliberately
#: no "allow": §5.2 forbids untrusted data authorising a tool call, and a
#: configuration switch that permits it is the invariant turned off.
UNTRUSTED_ARG_POLICIES = frozenset({"deny", "require_approval", "approve"})

#: Approval categories matched against the caller's hints. Any other entry in
#: `require_approval_for` must name a tool on the same agent's allow-list.
APPROVAL_CATEGORIES = frozenset({"irreversible", "high_impact"})

#: Keys the engine understands in an `argument_constraints` entry. An unknown
#: key is almost always a typo for one of these, and would silently constrain
#: nothing.
CONSTRAINT_KEYS = frozenset({"allowed_values", "max_length", "pattern"})

#: Keys the engine understands in a `tool_configs.<tool>` entry. A typo such
#: as `argument_shema` would otherwise silently remove the schema check.
TOOL_CONFIG_KEYS = frozenset({"argument_schema", "argument_constraints"})


def validate_agent_policy(agent_policy: Any) -> list[str]:
    """Return every problem with one agent entry; empty means valid."""
    if not isinstance(agent_policy, dict):
        return ["agent policy must be an object"]

    errors: list[str] = []

    allowed = agent_policy.get("allowed_tools")
    allowed_names: set[str] = set()
    if "allowed_tools" not in agent_policy:
        errors.append(
            "missing 'allowed_tools' — the engine denies every tool without it; "
            "use [] to deny every tool explicitly"
        )
    elif not isinstance(allowed, list) or not all(isinstance(t, str) for t in allowed):
        errors.append("'allowed_tools' must be a list of tool-name strings")
    else:
        allowed_names = set(allowed)

    uap = agent_policy.get("untrusted_arg_policy", "require_approval")
    # isinstance first: membership in a set hashes the value, and an
    # unhashable one (a list) would raise instead of being reported.
    if not isinstance(uap, str) or uap not in UNTRUSTED_ARG_POLICIES:
        errors.append(
            f"'untrusted_arg_policy' is {uap!r}; accepted values are "
            f"{sorted(UNTRUSTED_ARG_POLICIES)} — untrusted data may never "
            "authorise a tool call (PRD §5.2)"
        )

    raf = agent_policy.get("require_approval_for", [])
    if not isinstance(raf, list):
        errors.append("'require_approval_for' must be a list")
    else:
        unknown = [
            x for x in raf
            if not isinstance(x, str) or (x not in APPROVAL_CATEGORIES and x not in allowed_names)
        ]
        if unknown:
            errors.append(
                f"'require_approval_for' has unrecognised entries {unknown}; each entry "
                f"must be one of {sorted(APPROVAL_CATEGORIES)} or a tool on this "
                "agent's 'allowed_tools'"
            )

    rate_limits = agent_policy.get("rate_limits", {})
    if not isinstance(rate_limits, dict):
        errors.append("'rate_limits' must be an object")
    elif "tool_calls_per_minute" in rate_limits and not _is_positive_int(
        rate_limits["tool_calls_per_minute"]
    ):
        errors.append("'rate_limits.tool_calls_per_minute' must be a positive integer")

    errors.extend(_validate_tool_configs(agent_policy.get("tool_configs", {})))
    return errors


def validate_policy_document(policy_data: Any) -> list[str]:
    """Return every problem with a whole policy document; empty means valid."""
    if not isinstance(policy_data, dict):
        return ["policy must be a YAML/JSON object"]

    errors: list[str] = []
    if "memory" not in policy_data:
        errors.append("policy missing required 'memory' section")

    agents = policy_data.get("agents")
    if not isinstance(agents, dict):
        errors.append("policy missing required 'agents' object")
        return errors
    if "default" not in agents:
        errors.append(
            "'agents' must define a 'default' agent — it is the fallback for every "
            "unconfigured agent_id; use allowed_tools: [] to make it deny-all"
        )
    for name, agent_policy in agents.items():
        errors.extend(f"agent {name!r}: {e}" for e in validate_agent_policy(agent_policy))
    return errors


def _is_positive_int(value: Any) -> bool:
    # bool is an int subclass; `True` as a rate limit is a typo, not 1.
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_tool_configs(tool_configs: Any) -> list[str]:
    if not isinstance(tool_configs, dict):
        return ["'tool_configs' must be an object"]
    errors: list[str] = []
    for tool, config in tool_configs.items():
        if not isinstance(config, dict):
            errors.append(f"tool_configs.{tool}: must be an object")
            continue
        errors.extend(
            f"tool_configs.{tool}: unknown key {k!r}" for k in config if k not in TOOL_CONFIG_KEYS
        )
        if "argument_schema" in config:
            errors.extend(
                f"tool_configs.{tool}: {e}" for e in _validate_schema(config["argument_schema"])
            )
        constraints = config.get("argument_constraints", {})
        if not isinstance(constraints, dict):
            errors.append(f"tool_configs.{tool}: 'argument_constraints' must be an object")
            continue
        for arg, constraint in constraints.items():
            errors.extend(
                f"tool_configs.{tool}.{arg}: {e}" for e in _validate_constraint(constraint)
            )
    return errors


def _validate_constraint(constraint: Any) -> list[str]:
    """Each shape the engine would deny on (engine._check_value_constraints)."""
    if not isinstance(constraint, dict):
        return ["constraint must be an object"]
    errors = [f"unknown constraint key {k!r}" for k in constraint if k not in CONSTRAINT_KEYS]
    if "allowed_values" in constraint and not isinstance(constraint["allowed_values"], list):
        errors.append("'allowed_values' must be a list")
    if "max_length" in constraint and not _is_positive_int(constraint["max_length"]):
        errors.append("'max_length' must be a positive integer")
    if "pattern" in constraint:
        pattern = constraint["pattern"]
        if not isinstance(pattern, str):
            errors.append("'pattern' must be a string")
        else:
            try:
                re.compile(pattern)
            # OverflowError/RecursionError: e.g. `a{99999999999}` is not an re.error.
            except (re.error, OverflowError, RecursionError) as e:
                errors.append(f"'pattern' does not compile ({e})")
    return errors


def _validate_schema(schema: Any) -> list[str]:
    """`argument_schema` must be a valid JSON Schema object.

    A malformed one is not a bypass (the engine denies every call to the tool),
    but it is a silent outage that should surface at write time instead.
    """
    if not isinstance(schema, dict):
        return ["'argument_schema' must be an object"]
    try:
        import jsonschema
    except ImportError:  # [server] extra absent: the engine denies at runtime anyway
        return []
    try:
        jsonschema.validators.validator_for(schema).check_schema(schema)
    except jsonschema.exceptions.SchemaError as e:
        return [f"'argument_schema' is not a valid JSON Schema ({e.message})"]
    return []
