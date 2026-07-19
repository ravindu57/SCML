"""
§6.8 — Policy Store and Control Plane.

Provides versioned declarative policy storage with:
  - CRUD + rollback (FR-CP-01)
  - Shadow → enforce staged rollout (FR-CP-02)
  - Control-plane / data-plane isolation (FR-CP-03)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
import structlog

from trust_mediator.db.policy_repo import PolicyRepository, PolicyVersionORM

logger = structlog.get_logger(__name__)


class PolicyStore:
    """
    High-level policy store used by the control plane API.
    The data plane reads policy via PolicyLoader (which uses the same DB
    but is isolated from control-plane writes via caching and validation).
    """

    def __init__(self, repo: PolicyRepository | None = None) -> None:
        self._repo = repo or PolicyRepository()

    async def get_active(self) -> dict[str, Any] | None:
        return await self._repo.get_active_policy()

    async def get_active_version(self) -> PolicyVersionORM | None:
        return await self._repo.get_active_version()

    async def create_version(
        self,
        policy_data: dict[str, Any],
        description: str = "",
        created_by: str = "api",
        activate: bool = True,
        shadow: bool = False,
    ) -> PolicyVersionORM:
        """Validate and create a new policy version."""
        errors = self._validate(policy_data)
        if errors:
            raise ValueError(f"Policy validation failed: {errors}")

        version = await self._repo.create_version(
            policy_data=policy_data,
            description=description,
            created_by=created_by,
            activate=activate,
            shadow=shadow,
        )
        logger.info(
            "policy_store.version_created",
            version=version.version_number,
            shadow=shadow,
            activate=activate,
        )
        return version

    async def rollback(self, version_id: str) -> bool:
        success = await self._repo.rollback(version_id)
        if success:
            logger.info("policy_store.rolled_back", version_id=version_id)
        return success

    async def list_versions(self, limit: int = 20) -> list[PolicyVersionORM]:
        return await self._repo.list_versions(limit=limit)

    async def bootstrap_from_yaml(self, path: Path | None = None) -> None:
        """Load the default YAML policy into the DB on first run."""
        existing = await self._repo.get_active_policy()
        if existing:
            logger.debug("policy_store.already_bootstrapped")
            return

        from trust_mediator.config import settings
        yaml_path = path or settings.policy_default_path
        if not yaml_path.exists():
            logger.warning("policy_store.yaml_not_found", path=str(yaml_path))
            return

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        await self.create_version(
            policy_data=data or {},
            description="Bootstrapped from default YAML",
            created_by="system",
            activate=True,
        )
        logger.info("policy_store.bootstrapped_from_yaml", path=str(yaml_path))

    @staticmethod
    def _validate(policy_data: dict[str, Any]) -> list[str]:
        """Basic structural validation of a policy document."""
        errors: list[str] = []
        if not isinstance(policy_data, dict):
            errors.append("Policy must be a YAML/JSON object")
            return errors
        if "agents" not in policy_data:
            errors.append("Policy missing required 'agents' section")
        if "memory" not in policy_data:
            errors.append("Policy missing required 'memory' section")
        return errors
