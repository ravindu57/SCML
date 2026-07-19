"""
API Key authentication dependency.

Keys are configured via the TRUST_MEDIATOR_API_KEYS environment variable
as a comma-separated list.  In development mode the key check is skipped
if the list is empty so the API stays usable out-of-the-box.

Usage in a router:
    from trust_mediator.api.auth import AuthDep

    @router.post("/v1/mediate/context")
    async def endpoint(request: ..., _: AuthDep):
        ...
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from trust_mediator.config import settings

_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def _validate_api_key(api_key: str | None = Security(_header_scheme)) -> str | None:
    """
    Validate the X-API-Key header.

    - In **development** mode with no keys configured: always passes through.
    - In **production** mode (or when keys are configured): rejects missing /
      invalid keys with HTTP 401.
    """
    configured_keys = settings.api_keys  # list[str]

    # No keys configured + dev mode → open access (original behaviour)
    if not configured_keys and settings.is_development:
        return None

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key not in configured_keys:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked API key",
        )

    return api_key


# Annotated dependency — import this in routers
AuthDep = Annotated[str | None, Depends(_validate_api_key)]
