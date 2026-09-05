"""
API key authentication.

Keys are configured via the TRUST_MEDIATOR_API_KEYS environment variable as a
comma-separated list. Each entry is either a bare key (``sk-abc123``) or a
named one (``alice:sk-abc123``) — see ``Settings.api_key_principals``.

The dependency resolves a key to a **principal**, and that is what handlers
receive. Two reasons it returns the principal rather than the key:

1. Admin actions must be attributable. FR-MI-05's release endpoint writes a
   reviewer name into the memory record and the audit chain; taking it from a
   query parameter meant the caller named their own reviewer. It now comes from
   whichever key authenticated the call, so it cannot be forged without one.
2. Handlers should never hold the raw secret. Anything a handler receives can
   end up in a log line, a span attribute, or an error body.

Unnamed keys resolve to a fingerprint (``key-<sha256 prefix>``), which
identifies *which* key acted without disclosing it.

Usage in a router:
    from trust_mediator.api.auth import AuthDep

    @router.post("/v1/mediate/context")
    async def endpoint(request: ..., _: AuthDep):
        ...

    # or, when the caller's identity matters:
    async def endpoint(request: ..., principal: AuthDep):
        ...
"""
from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Annotated, NamedTuple

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from trust_mediator.api import key_store
from trust_mediator.config import settings

_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

#: Principal for an unauthenticated caller in open development mode.
ANONYMOUS = "anonymous"


class Caller(NamedTuple):
    """Who made the request: the authenticated principal and its tenant.

    Handlers receive this instead of a bare string so policy operations can
    scope to the caller's tenant without ever touching the raw key. The fields
    are safe to log — no secret material is carried here.
    """

    tenant: str
    principal: str


def key_fingerprint(api_key: str) -> str:
    """A stable, non-secret identifier for a key.

    Safe to put in audit records, log lines and rate-limit bucket names — all
    places the key itself must never appear.
    """
    return "key-" + sha256(api_key.encode("utf-8")).hexdigest()[:12]


def tenant_for(api_key: str) -> str | None:
    """The tenant the key is bound to, or None if it is not configured.

    Walks every configured entry with :func:`hmac.compare_digest` and no early
    exit, exactly like :func:`principal_for` — ``key in keys`` would leak the
    key byte-by-byte through timing.
    """
    matched: str | None = None
    probe = api_key.encode("utf-8")
    for entry in key_store.entries():
        if hmac.compare_digest(probe, entry.key.encode("utf-8")):
            matched = entry.tenant or settings.default_tenant
    return matched


def caller_for(api_key: str) -> Caller | None:
    """Resolve a key to its (tenant, principal), or None if not configured."""
    matched: Caller | None = None
    probe = api_key.encode("utf-8")
    for entry in key_store.entries():
        if hmac.compare_digest(probe, entry.key.encode("utf-8")):
            matched = Caller(
                tenant=entry.tenant or settings.default_tenant,
                principal=entry.name or key_fingerprint(entry.key),
            )
    return matched


def principal_for(api_key: str) -> str | None:
    """Resolve a key to its principal, or None if it is not configured.

    Compares against every configured key with :func:`hmac.compare_digest` and
    without an early exit. ``key in settings.api_keys`` short-circuits on the
    first differing byte, which leaks how much of a guess is correct and makes
    the key recoverable byte-by-byte from response timing.
    """
    matched: str | None = None
    probe = api_key.encode("utf-8")
    for name, candidate in key_store.principals():
        if hmac.compare_digest(probe, candidate.encode("utf-8")):
            matched = name or key_fingerprint(candidate)
    return matched


def configured_principals() -> list[tuple[str | None, str]]:
    """The active key set, from the env var or a rotating key file."""
    return key_store.principals()


def open_access_allowed() -> bool:
    """Whether unauthenticated callers are let through.

    Development convenience applies only when *no key source is configured at
    all*. Pointing TRUST_MEDIATOR_API_KEYS_FILE at a file is a statement that
    this deployment authenticates, so an empty file means "every key is
    revoked" — in every environment.

    Without that distinction, emptying the key file to revoke access would
    instead open the API to everyone in development, which is the exact
    opposite of the operator's intent and the failure mode they would be least
    likely to check for.
    """
    if settings.api_keys_file:
        return False
    return settings.is_development and not key_store.principals()


def _validate_api_key(api_key: str | None = Security(_header_scheme)) -> str:
    """
    Validate the X-API-Key header and return the caller's principal.

    - In **development** mode with no keys configured: returns ANONYMOUS.
    - Otherwise: rejects missing keys with 401 and unknown keys with 403.
    """
    if open_access_allowed():
        return ANONYMOUS

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    principal = principal_for(api_key)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked API key",
        )

    return principal


def _validate_caller(
    api_key: str | None = Security(_header_scheme),
    principal: str = Depends(_validate_api_key),
) -> Caller:
    """
    Validate the X-API-Key header and return the caller's tenant + principal.

    The **tenant is derived from the key, never from the request body**. A
    caller cannot claim another company's policy by sending a ``tenant_id``
    field, because no mediation or policy request model accepts one — the
    tenant is read off the authenticated key here and the handlers that need
    scoping take ``CallerDep`` instead of a client-controlled value.

    ``principal`` is resolved through :func:`_validate_api_key` so this
    dependency's graph contains the same validation every other route relies
    on (and so the structural auth-walk test keeps passing). The tenant is then
    resolved by comparing the header against every configured entry with
    ``hmac.compare_digest`` and no early exit.
    """
    if open_access_allowed():
        return Caller(tenant=settings.default_tenant, principal=principal)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    caller = caller_for(api_key)
    if caller is None:
        # Unreachable: _validate_api_key already raised for an unknown key.
        # Fail closed rather than trust an inconsistent auth state.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked API key",
        )
    return caller


# Annotated dependency — import this in routers. Resolves to the caller's
# principal name, never the key.
AuthDep = Annotated[str, Depends(_validate_api_key)]

# Annotated dependency — import this in routers that must scope by tenant.
# Resolves to a Caller (tenant + principal); the raw key never leaves auth.py.
CallerDep = Annotated[Caller, Depends(_validate_caller)]
