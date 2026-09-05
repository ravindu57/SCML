"""
GET/PUT /v1/policy — policy control plane endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from trust_mediator.api.auth import CallerDep
from trust_mediator.api.dependencies import PolicyStoreDep

router = APIRouter(prefix="/v1/policy", tags=["policy"])


class PolicyUpdateRequest(BaseModel):
    policy_data: dict[str, Any]
    description: str = ""
    created_by: str = "api"
    activate: bool = True
    shadow: bool = False


class AgentPolicyRequest(BaseModel):
    agent_policy: dict[str, Any]
    description: str = ""


class PolicyVersionResponse(BaseModel):
    id: str
    version_number: int
    description: str
    is_active: bool
    is_shadow: bool
    created_by: str
    created_at: str
    activated_at: str | None = None


@router.get("", summary="Get the active policy")
async def get_policy(store: PolicyStoreDep, caller: CallerDep):
    """FR-CP-01: Return the active security policy for the caller's tenant.

    The tenant is resolved from the authenticated key, so this endpoint shows
    each company its own document — never another tenant's, and never the
    global default once the company has its own.
    """
    policy = await store.get_active(tenant_id=caller.tenant)
    if policy is None:
        raise HTTPException(status_code=404, detail="No active policy found")
    version = await store.get_active_version(tenant_id=caller.tenant)
    return {
        "tenant": caller.tenant,
        "version": version.version_number if version else None,
        "policy": policy,
        "shadow": version.is_shadow if version else False,
    }


@router.put("", summary="Create a new policy version")
async def update_policy(request: PolicyUpdateRequest, store: PolicyStoreDep, caller: CallerDep):
    """FR-CP-01, FR-CP-02: Create a new policy version in the caller's tenant.

    ``created_by`` stays a request field (documented choice: this endpoint is
    the bootstrap/wholesale path) but the version is written into the caller's
    tenant namespace, so a tenant with its own key cannot overwrite the global
    document or another company's.
    """
    try:
        version = await store.create_version(
            policy_data=request.policy_data,
            description=request.description,
            created_by=request.created_by,
            activate=request.activate,
            shadow=request.shadow,
            tenant_id=caller.tenant,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return PolicyVersionResponse(
        id=version.id,
        version_number=version.version_number,
        description=version.description,
        is_active=version.is_active,
        is_shadow=version.is_shadow,
        created_by=version.created_by,
        created_at=version.created_at.isoformat(),
        activated_at=version.activated_at.isoformat() if version.activated_at else None,
    )


def _version_response(version) -> PolicyVersionResponse:
    return PolicyVersionResponse(
        id=version.id,
        version_number=version.version_number,
        description=version.description,
        is_active=version.is_active,
        is_shadow=version.is_shadow,
        created_by=version.created_by,
        created_at=version.created_at.isoformat(),
        activated_at=version.activated_at.isoformat() if version.activated_at else None,
    )


@router.get("/agents/{agent_id}", summary="Get one agent's policy")
async def get_agent_policy(agent_id: str, store: PolicyStoreDep, caller: CallerDep):
    """FR-CP-01: the policy for a single agent in the caller's tenant.

    404 means the agent has no policy of its own and therefore falls back to
    `default`, which is deny-all — worth distinguishing from an agent that is
    configured but permissive.
    """
    agent_policy = await store.get_agent(agent_id, tenant_id=caller.tenant)
    if agent_policy is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"agent '{agent_id}' has no policy; it falls back to 'default', "
                f"which is deny-all"
            ),
        )
    return {"tenant": caller.tenant, "agent_id": agent_id, "policy": agent_policy}


@router.put("/agents/{agent_id}", summary="Create or replace one agent's policy")
async def upsert_agent_policy(
    agent_id: str,
    request: AgentPolicyRequest,
    store: PolicyStoreDep,
    caller: CallerDep,
):
    """FR-CP-01: replace one agent's policy in the caller's tenant.

    `PUT /v1/policy` replaces the whole document, `agents` map included, so two
    teams administering different agents through it clobber each other — last
    write wins, and the loser is silently deny-alled via the `default`
    fallback. This is the endpoint that makes a shared mediator workable, and
    the tenant scoping keeps each company's agents in their own document.

    The read-modify-write happens inside one locked transaction in the
    repository, so concurrent updates to different agents serialise instead of
    overwriting each other.

    `created_by` is the authenticated principal, not a request field: a policy
    change is an administrative action and the version history should record
    who made it rather than what they typed.
    """
    try:
        version = await store.upsert_agent(
            agent_id=agent_id,
            agent_policy=request.agent_policy,
            description=request.description,
            created_by=caller.principal,
            tenant_id=caller.tenant,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _version_response(version)


@router.delete("/agents/{agent_id}", summary="Remove one agent's policy")
async def delete_agent_policy(agent_id: str, store: PolicyStoreDep, caller: CallerDep):
    """FR-CP-01: remove one agent from the caller's tenant, leaving the rest intact.

    The agent then falls back to `default` and is denied everything. That is
    the point: revoking a policy should stop the agent, not leave it running
    unconfigured.
    """
    if await store.get_agent(agent_id, tenant_id=caller.tenant) is None:
        raise HTTPException(status_code=404, detail=f"agent '{agent_id}' has no policy")
    try:
        version = await store.delete_agent(
            agent_id=agent_id, created_by=caller.principal, tenant_id=caller.tenant
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _version_response(version)


@router.get("/versions", summary="List policy version history")
async def list_versions(limit: int = 20, store: PolicyStoreDep = None, caller: CallerDep = None):
    """Return the caller's tenant version history."""
    versions = await store.list_versions(limit=limit, tenant_id=caller.tenant if caller else "default")
    return [
        PolicyVersionResponse(
            id=v.id,
            version_number=v.version_number,
            description=v.description,
            is_active=v.is_active,
            is_shadow=v.is_shadow,
            created_by=v.created_by,
            created_at=v.created_at.isoformat(),
            activated_at=v.activated_at.isoformat() if v.activated_at else None,
        )
        for v in versions
    ]


@router.post("/rollback/{version_id}", summary="Rollback to a previous policy version")
async def rollback(version_id: str, store: PolicyStoreDep, caller: CallerDep):
    """FR-CP-01: Reactivate a previous version of the caller's tenant.

    The target version must belong to the caller's tenant; another tenant's
    version id is treated as not found.
    """
    success = await store.rollback(version_id, tenant_id=caller.tenant)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy version '{version_id}' not found")
    return {"rolled_back": True, "version_id": version_id}
