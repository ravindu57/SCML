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
from trust_mediator.modules.tool_policy.validation import (
    validate_agent_policy,
    validate_policy_document,
)

logger = structlog.get_logger(__name__)


class PolicyStore:
    """
    High-level policy store used by the control plane API.
    The data plane reads policy via PolicyLoader (which uses the same DB
    but is isolated from control-plane writes via caching and validation).
    """

    def __init__(self, repo: PolicyRepository | None = None) -> None:
        self._repo = repo or PolicyRepository()

    async def get_active(self, tenant_id: str = "default") -> dict[str, Any] | None:
        return await self._repo.get_active_policy(tenant_id=tenant_id)

    async def get_active_version(self, tenant_id: str = "default") -> PolicyVersionORM | None:
        return await self._repo.get_active_version(tenant_id=tenant_id)

    async def create_version(
        self,
        policy_data: dict[str, Any],
        description: str = "",
        created_by: str = "api",
        activate: bool = True,
        shadow: bool = False,
        tenant_id: str = "default",
    ) -> PolicyVersionORM:
        """Validate and create a new policy version for a tenant.

        FR-CP-02: a shadow version must not be active. Nothing evaluates a
        policy in shadow — the data plane enforces whichever version is active
        — so ``shadow=True, activate=True`` used to enforce the document live
        while every listing reported it as shadow. Refused rather than
        silently downgraded to either flag, because the two readings
        (enforce now / do not enforce) are opposite. Stage a version with
        ``activate=False`` and promote it with rollback.
        """
        if shadow and activate:
            raise ValueError(
                "Policy validation failed: ['a shadow version cannot be activated: "
                "shadow evaluation is not implemented, so an active shadow version "
                "would be enforced. Create it with activate=false and promote it "
                "with POST /v1/policy/rollback/{version_id}']"
            )
        errors = self._validate(policy_data)
        if errors:
            raise ValueError(f"Policy validation failed: {errors}")

        version = await self._repo.create_version(
            policy_data=policy_data,
            description=description,
            created_by=created_by,
            activate=activate,
            shadow=shadow,
            tenant_id=tenant_id,
        )
        logger.info(
            "policy_store.version_created",
            tenant_id=tenant_id,
            version=version.version_number,
            shadow=shadow,
            activate=activate,
        )
        return version

    async def get_agent(self, agent_id: str, tenant_id: str = "default") -> dict[str, Any] | None:
        """One agent's policy for a tenant, or None if it has none of its own."""
        policy = await self._repo.get_active_policy(tenant_id=tenant_id) or {}
        return (policy.get("agents") or {}).get(agent_id)

    async def upsert_agent(
        self,
        agent_id: str,
        agent_policy: dict[str, Any],
        description: str = "",
        created_by: str = "api",
        tenant_id: str = "default",
    ) -> PolicyVersionORM:
        """Replace one agent's policy, leaving the rest of the document alone.

        This is the endpoint that makes SCML usable by more than one team.
        `create_version` replaces the whole document including the `agents`
        map, so two teams administering different agents through it means last
        write wins and the loser is silently deny-alled via the `default`
        fallback — no error, just an agent that stops working.

        The `default` agent is refused here on purpose. It is the deny-all
        fallback every unconfigured agent lands on, so widening it through a
        per-agent call would quietly grant authority to every agent nobody has
        configured yet. Changing it is a whole-document decision, and
        `PUT /v1/policy` is where that belongs.
        """
        if agent_id == "default":
            raise ValueError(
                "refusing to modify the 'default' agent through the per-agent "
                "endpoint: it is the deny-all fallback for every unconfigured "
                "agent. Use PUT /v1/policy if that is genuinely intended."
            )
        errors = self._validate_agent(agent_policy)
        if errors:
            raise ValueError(f"Agent policy validation failed: {errors}")

        version = await self._repo.upsert_agent(
            agent_id=agent_id,
            agent_policy=agent_policy,
            description=description or f"Update agent '{agent_id}'",
            created_by=created_by,
            tenant_id=tenant_id,
        )
        logger.info(
            "policy_store.agent_upserted",
            tenant_id=tenant_id,
            agent_id=agent_id,
            version=version.version_number,
        )
        return version

    async def delete_agent(
        self, agent_id: str, created_by: str = "api", tenant_id: str = "default"
    ) -> PolicyVersionORM:
        """Remove one agent, leaving the rest of the document alone.

        The agent then falls back to `default`, which is deny-all. That is the
        intended meaning of deleting a policy: revoke the authority, do not
        leave the agent running unconfigured.
        """
        if agent_id == "default":
            raise ValueError("refusing to delete the 'default' deny-all agent")
        version = await self._repo.upsert_agent(
            agent_id=agent_id,
            agent_policy=None,
            description=f"Remove agent '{agent_id}'",
            created_by=created_by,
            tenant_id=tenant_id,
        )
        logger.info(
            "policy_store.agent_deleted",
            tenant_id=tenant_id,
            agent_id=agent_id,
            version=version.version_number,
        )
        return version

    async def rollback(self, version_id: str, tenant_id: str = "default") -> bool:
        success = await self._repo.rollback(
            version_id, tenant_id=tenant_id, validator=validate_policy_document
        )
        if success:
            logger.info(
                "policy_store.rolled_back", tenant_id=tenant_id, version_id=version_id
            )
        return success

    async def list_versions(self, limit: int = 20, tenant_id: str = "default") -> list[PolicyVersionORM]:
        return await self._repo.list_versions(limit=limit, tenant_id=tenant_id)

    async def bootstrap_from_yaml(self, path: Path | None = None) -> None:
        """Load the default YAML policy into the *default tenant* on first run.

        Tenancy: only the default (unqualified) tenant is seeded this way. A
        tenant-qualified company starts with **no policy at all**, which the
        data plane renders as deny-all — the same bootstrap principle as the
        `default` agent. The company's admin provisions its own policy through
        PUT /v1/policy with its own key.

        An invalid YAML raises (via ``create_version``) and aborts startup.
        That is deliberate and fail-closed: the alternative, starting with no
        seeded policy, would be served as deny-all by the loader anyway, and a
        loud start-up failure tells the operator why rather than leaving every
        tool call mysteriously denied.
        """
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
    def _validate_agent(agent_policy: dict[str, Any]) -> list[str]:
        """Validate a single agent entry (see ``tool_policy/validation.py``)."""
        return validate_agent_policy(agent_policy)

    @staticmethod
    def _validate(policy_data: dict[str, Any]) -> list[str]:
        """Validate a whole document, every agent included.

        This used to check only that `agents` and `memory` existed, so
        `{"agents": {}, "memory": {}}` was stored and, read by an engine that
        took a missing `allowed_tools` as "no restriction", authorised every
        tool for every agent in the tenant.
        """
        return validate_policy_document(policy_data)
