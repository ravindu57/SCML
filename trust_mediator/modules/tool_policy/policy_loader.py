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

from trust_mediator.modules.tool_policy.validation import validate_policy_document

logger = structlog.get_logger(__name__)

#: Effective default from config, kept here only for the tenant fallback below
#: so the loader does not need to import settings lazily in hot-path calls.
DEFAULT_TENANT = "default"


#: Deny-all document a tenant falls back to when it has no policy of its own.
#: A tenant that enrols no policy must be denied, not unrestricted — §9
#: fail-closed applies at the tenant boundary just as at the agent boundary.
#: The engine now denies on an absent ``allowed_tools`` too, but the fallback
#: still carries an explicit ``[]`` default agent so it is a valid document
#: in its own right (``validation.validate_policy_document``) and does not
#: depend on that backstop.
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
    #: How long the last DB document may stand in for the DB during an outage.
    #: Bounded because a tool revoked through another worker during the outage
    #: would otherwise stay granted here until the DB comes back.
    _LAST_GOOD_MAX_AGE = 10 * _CACHE_TTL
    #: After a DB error, serve the fallback this long before trying the DB
    #: again, so every request does not wait out a connect timeout.
    _ERROR_BACKOFF = 2.0

    def __init__(
        self,
        policy_repo: Any = None,
        default_path: Path | None = None,
    ) -> None:
        self._repo = policy_repo
        self._default_path = default_path
        self._memory_cache: dict[str, dict[str, Any]] = {}
        self._cache_loaded_at: dict[str, float] = {}
        # Last document actually read from the DB, per tenant, kept past the
        # TTL so a DB outage serves what the DB last said rather than a file.
        self._last_good: dict[str, tuple[float, dict[str, Any]]] = {}
        self._error_until: dict[str, float] = {}

    async def get_policy(self, tenant_id: str = DEFAULT_TENANT) -> dict[str, Any]:
        """Return the tenant's active policy, using cache if fresh."""
        now = time.monotonic()
        cached = self._memory_cache.get(tenant_id)
        if cached is not None and (now - self._cache_loaded_at.get(tenant_id, 0.0)) < self._CACHE_TTL:
            return cached

        # In error backoff: serve the outage fallback without touching the DB.
        if self._repo is not None and now < self._error_until.get(tenant_id, 0.0):
            return self._outage_policy(tenant_id, now)

        # Try DB (scoped by tenant)
        if self._repo is not None:
            try:
                policy = await self._repo.get_active_policy(tenant_id=tenant_id)
                if policy:
                    self._memory_cache[tenant_id] = policy
                    self._cache_loaded_at[tenant_id] = now
                    self._last_good[tenant_id] = (now, policy)
                    self._error_until.pop(tenant_id, None)
                    return policy
            except Exception as e:
                # Never the YAML here (security review Sec #16): a tool revoked
                # in the DB but still listed in the gateway file would be
                # re-granted for the length of the outage. Serve the last
                # document the DB returned, else deny-all, and cache neither,
                # so recovery is picked up on the next call.
                logger.warning(
                    "policy_loader.db_error", tenant_id=tenant_id, error_type=type(e).__name__
                )
                self._error_until[tenant_id] = now + self._ERROR_BACKOFF
                return self._outage_policy(tenant_id, now)

        # The DB answered and holds no document (or there is no DB): the
        # default tenant bootstraps from the gateway YAML; a tenant-qualified
        # company with no document is deny-all.
        if tenant_id == DEFAULT_TENANT:
            policy = self._load_default_yaml()
        else:
            policy = _TENANT_DENY_ALL
        self._memory_cache[tenant_id] = policy
        self._cache_loaded_at[tenant_id] = now
        return policy

    def _outage_policy(self, tenant_id: str, now: float) -> dict[str, Any]:
        """Last DB document if recent enough, else deny-all. Never the YAML."""
        last = self._last_good.get(tenant_id)
        if last is not None and now - last[0] <= self._LAST_GOOD_MAX_AGE:
            logger.warning("policy_loader.serving_last_good", tenant_id=tenant_id)
            return last[1]
        logger.error("policy_loader.db_error_deny_all", tenant_id=tenant_id)
        return _TENANT_DENY_ALL

    def _load_default_yaml(self) -> dict[str, Any]:
        path = self._default_path
        if path is None:
            from trust_mediator.config import settings
            path = settings.policy_default_path

        try:
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f)
                # The gateway YAML reaches the engine without passing through
                # PolicyStore, so it is validated here too; an invalid file is
                # served as deny-all rather than as written (§9).
                errors = validate_policy_document(data)
                if errors:
                    logger.error(
                        "policy_loader.yaml_invalid_deny_all", path=str(path), errors=errors
                    )
                    return _TENANT_DENY_ALL.copy()
                logger.info("policy_loader.loaded_from_yaml", path=str(path))
                return data
        except Exception as e:
            logger.error("policy_loader.yaml_error", error=str(e))

        logger.warning("policy_loader.using_hardcoded_defaults")
        return _TENANT_DENY_ALL.copy()

    def invalidate_cache(self) -> None:
        """Force next call to get_policy() to re-fetch from DB."""
        self._memory_cache = {}
        self._cache_loaded_at = {}
        self._last_good = {}
        self._error_until = {}