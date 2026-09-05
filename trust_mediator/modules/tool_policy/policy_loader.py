"""
§6.4 — Tool-Call Policy Engine: declarative policy loading.

Loads policy from the database (with in-process hot cache) and provides a
structured view of the active policy for the engine to evaluate.

Resolution is **per tenant**. A tenant-qualified key binds a company to its
own policy document (see ``trust_mediator/config.py`` key parsing and
``trust_mediator/api/auth.py`` ``CallerDep``); the engine asks for the policy
of ``request.tenant_id`` and never sees another tenant's document.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)

#: Effective default from config, kept here only for the tenant fallback below
#: so the loader does not need to import settings lazily in hot-path calls.
DEFAULT_TENANT = "default"


#: Deny-all document a tenant falls back to when it has no policy of its own.
#: A tenant that enrols no policy must be denied, not unrestricted — §9
#: fail-closed applies at the tenant boundary just as at the agent boundary.
#: The engine treats an absent ``allowed_tools`` as "no restriction", so the
#: fallback *must* carry an explicit ``[]`` default agent; returning
#: ``{"agents": {}}`` would fail open.
_TENANT_DENY_ALL: dict[str, Any] = {
    "agents": {
        "default": {
            "allowed_tools": [],
            "require_approval_for": ["irreversible", "high_impact"],
            "untrusted_arg_policy": "require_approval",
            "rate_limits": {"tool_calls_per_minute": 60},
        }
    },
    "memory": {
        "integrity_score_threshold": 0.65,
        "rescan_on_read": False,
    },
    "scanner": {
        "shadow_mode": False,
        "thresholds": {
            "block": 0.85,
            "escalate": 0.70,
            "transform": 0.50,
        },
    },
    "redaction": {
        "pii_patterns_enabled": True,
        "entropy_threshold": 4.5,
        "protected_classes": ["pii", "secret", "credential"],
    },
}


class PolicyLoader:
    """
    Loads and caches the active declarative security policy.

    Policy resolution order per tenant:
      1. In-process cache (TTL 30s)
      2. Database (PolicyRepository)
      3. Gateway YAML file (+ hardcoded defaults) — **default tenant only**.
         A tenant-qualified company with no DB document is deny-all.
    """

    _CACHE_TTL = 30  # seconds

    def __init__(
        self,
        policy_repo: Any = None,
        default_path: Path | None = None,
    ) -> None:
        self._repo = policy_repo
        self._default_path = default_path
        self._memory_cache: dict[str, dict[str, Any]] = {}
        self._cache_loaded_at: dict[str, float] = {}

    async def get_policy(self, tenant_id: str = DEFAULT_TENANT) -> dict[str, Any]:
        """Return the tenant's active policy, using cache if fresh."""
        now = time.monotonic()
        cached = self._memory_cache.get(tenant_id)
        if cached is not None and (now - self._cache_loaded_at.get(tenant_id, 0.0)) < self._CACHE_TTL:
            return cached

        # Try DB (scoped by tenant)
        if self._repo is not None:
            try:
                policy = await self._repo.get_active_policy(tenant_id=tenant_id)
                if policy:
                    self._memory_cache[tenant_id] = policy
                    self._cache_loaded_at[tenant_id] = now
                    return policy
            except Exception as e:
                logger.warning(
                    "policy_loader.db_error", tenant_id=tenant_id, error=str(e)
                )

        # Fallback: default tenant honours the gateway YAML + hardcoded defaults;
        # a tenant-qualified company with no document is deny-all.
        if tenant_id == DEFAULT_TENANT:
            policy = self._load_default_yaml()
        else:
            policy = _TENANT_DENY_ALL
        self._memory_cache[tenant_id] = policy
        self._cache_loaded_at[tenant_id] = now
        return policy

    def _load_default_yaml(self) -> dict[str, Any]:
        path = self._default_path
        if path is None:
            from trust_mediator.config import settings
            path = settings.policy_default_path

        try:
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f)
                    logger.info("policy_loader.loaded_from_yaml", path=str(path))
                    return data or {}
        except Exception as e:
            logger.error("policy_loader.yaml_error", error=str(e))

        logger.warning("policy_loader.using_hardcoded_defaults")
        return _TENANT_DENY_ALL.copy()

    def invalidate_cache(self) -> None:
        """Force next call to get_policy() to re-fetch from DB."""
        self._memory_cache = {}
        self._cache_loaded_at = {}