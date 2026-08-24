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

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """One agent's policy, or None if it has none of its own."""
        policy = await self._repo.get_active_policy() or {}
        return (policy.get("agents") or {}).get(agent_id)

    async def upsert_agent(
        self,
        agent_id: str,
        agent_policy: dict[str, Any],
        description: str = "",
        created_by: str = "api",
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
        )
        logger.info(
            "policy_store.agent_upserted",
            agent_id=agent_id,
            version=version.version_number,
        )
        return version

    async def delete_agent(
        self, agent_id: str, created_by: str = "api"
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
        )
        logger.info(
            "policy_store.agent_deleted",
            agent_id=agent_id,
            version=version.version_number,
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
    def _validate_agent(agent_policy: dict[str, Any]) -> list[str]:
        """Validate a single agent entry.

        Deliberately narrow. The engine treats an absent `allowed_tools` as "no
        restriction" and an empty list as "deny everything" (engine.py:79), so a
        typo in that key is the difference between a locked-down agent and an
        unrestricted one — with no error either way. Requiring the key makes
        that choice explicit.

        `untrusted_arg_policy` and `require_approval_for` are checked against
        the values the engine actually branches on, because an unrecognised
        value there fails open: the engine matches "deny" and
        "require_approval"/"approve" and falls through to allow on anything
        else, so `untrusted_arg_policy: denied` would silently permit every
        tainted argument.
        """
        errors: list[str] = []
        if not isinstance(agent_policy, dict):
            return ["Agent policy must be an object"]

        if "allowed_tools" not in agent_policy:
            errors.append(
                "missing 'allowed_tools' — omit it and the engine applies no "
                "tool restriction at all; use [] to deny every tool"
            )
        elif not isinstance(agent_policy["allowed_tools"], list):
            errors.append("'allowed_tools' must be a list")

        uap = agent_policy.get("untrusted_arg_policy", "require_approval")
        if uap not in ("deny", "require_approval", "approve", "allow"):
            errors.append(
                f"'untrusted_arg_policy' is {uap!r}; the engine only matches "
                "'deny', 'require_approval'/'approve' and 'allow', and falls "
                "through to allow on anything else"
            )

        raf = agent_policy.get("require_approval_for", [])
        if not isinstance(raf, list):
            errors.append("'require_approval_for' must be a list")
        else:
            unknown = [x for x in raf if x not in ("irreversible", "high_impact")]
            if unknown:
                errors.append(
                    f"'require_approval_for' has unrecognised entries {unknown}; "
                    "only 'irreversible' and 'high_impact' are checked"
                )
        return errors

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
