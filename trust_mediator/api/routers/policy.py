"""
GET/PUT /v1/policy — policy control plane endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from trust_mediator.api.auth import AuthDep
from trust_mediator.api.dependencies import PolicyStoreDep

router = APIRouter(prefix="/v1/policy", tags=["policy"])


class PolicyUpdateRequest(BaseModel):
    policy_data: dict[str, Any]
    description: str = ""
    created_by: str = "api"
    activate: bool = True
    shadow: bool = False


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
async def get_policy(store: PolicyStoreDep, _: AuthDep):
    """FR-CP-01: Return the currently active declarative security policy."""
    policy = await store.get_active()
    if policy is None:
        raise HTTPException(status_code=404, detail="No active policy found")
    version = await store.get_active_version()
    return {
        "version": version.version_number if version else None,
        "policy": policy,
        "shadow": version.is_shadow if version else False,
    }


@router.put("", summary="Create a new policy version")
async def update_policy(request: PolicyUpdateRequest, store: PolicyStoreDep, _: AuthDep):
    """FR-CP-01, FR-CP-02: Create a new policy version (validates before activating)."""
    try:
        version = await store.create_version(
            policy_data=request.policy_data,
            description=request.description,
            created_by=request.created_by,
            activate=request.activate,
            shadow=request.shadow,
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


@router.get("/versions", summary="List policy version history")
async def list_versions(limit: int = 20, store: PolicyStoreDep = None, _: AuthDep = None):
    """Return version history."""
    versions = await store.list_versions(limit=limit)
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
async def rollback(version_id: str, store: PolicyStoreDep, _: AuthDep):
    """FR-CP-01: Reactivate a previous policy version."""
    success = await store.rollback(version_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Policy version '{version_id}' not found")
    return {"rolled_back": True, "version_id": version_id}
