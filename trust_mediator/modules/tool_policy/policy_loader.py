"""
§6.4 — Tool-Call Policy Engine: declarative policy loading.

Loads policy from the database (with Redis/in-memory hot cache) and
provides a structured view of the active policy for the engine to evaluate.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)


class PolicyLoader:
    """
    Loads and caches the active declarative security policy.

    Policy resolution order:
      1. Hot cache (Redis or in-memory, TTL 30s)
      2. Database (PolicyRepository)
      3. Default policy file (YAML fallback for dev/first-boot)
    """

    _CACHE_TTL = 30  # seconds

    def __init__(
        self,
        policy_repo: Any = None,
        default_path: Path | None = None,
    ) -> None:
        self._repo = policy_repo
        self._default_path = default_path
        self._memory_cache: dict[str, Any] | None = None
        self._cache_loaded_at: float = 0.0

    async def get_policy(self) -> dict[str, Any]:
        """Return the active policy, using cache if fresh."""
        now = time.monotonic()
        if (
            self._memory_cache is not None
            and (now - self._cache_loaded_at) < self._CACHE_TTL
        ):
            return self._memory_cache

        # Try DB
        if self._repo is not None:
            try:
                policy = await self._repo.get_active_policy()
                if policy:
                    self._memory_cache = policy
                    self._cache_loaded_at = now
                    return policy
            except Exception as e:
                logger.warning("policy_loader.db_error", error=str(e))

        # Fallback: YAML file
        policy = self._load_default_yaml()
        self._memory_cache = policy
        self._cache_loaded_at = now
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
        return _HARDCODED_DEFAULTS.copy()

    def invalidate_cache(self) -> None:
        """Force next call to get_policy() to re-fetch from DB."""
        self._memory_cache = None
        self._cache_loaded_at = 0.0


# Hardcoded safe defaults — used only if DB and YAML are both unavailable
_HARDCODED_DEFAULTS: dict[str, Any] = {
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
