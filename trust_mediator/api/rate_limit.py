"""
Rate limiting for TrustMediator API.

Uses slowapi (FastAPI-native limiter built on limits + Redis or in-memory storage).

Configuration:
  - TRUST_MEDIATOR_RATE_LIMIT   default "200/minute" per IP/key
  - REDIS_URL                   if set, uses Redis as the shared counter backend
                                 (required for multi-worker / Kubernetes deployments)
                                 if empty, falls back to in-memory (single-instance only)

Usage in routers:
    from trust_mediator.api.rate_limit import limiter

    @router.post("/v1/mediate/context")
    @limiter.limit("200/minute")
    async def endpoint(request: Request, ...):
        ...

    # The raw `request: Request` parameter MUST be present in the endpoint signature
    # for slowapi to extract the IP/key.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from trust_mediator.config import settings


def _key_func(request) -> str:  # type: ignore[override]
    """
    Rate-limit key function.

    Priority:
      1. X-API-Key header (per-key limiting when auth is active)
      2. X-Forwarded-For / client IP (fallback for open dev mode)
    """
    api_key = request.headers.get("X-API-Key")
    if api_key and api_key in settings.api_keys:
        return f"apikey:{api_key}"
    return get_remote_address(request)


# ── Limiter instance ─────────────────────────────────────────────────────────
# Use Redis backend when available, fall back to in-memory for dev/single-node.
# in_memory_fallback_enabled=True: if Redis is temporarily unreachable at startup
# (Docker race condition), the limiter switches to in-memory automatically.
_storage_uri = settings.redis_url or "memory://"

limiter = Limiter(
    key_func=_key_func,
    default_limits=[settings.rate_limit],
    storage_uri=_storage_uri,
    strategy="fixed-window",
    swallow_errors=True,              # don't let limiter errors crash requests
    in_memory_fallback_enabled=True,  # survive Redis startup race conditions
)
