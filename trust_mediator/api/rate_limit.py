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

from trust_mediator.api.auth import principal_for
from trust_mediator.config import settings


def _key_func(request) -> str:  # type: ignore[override]
    """
    Rate-limit key function.

    Priority:
      1. X-API-Key header (per-principal limiting when auth is active)
      2. X-Forwarded-For / client IP (fallback for open dev mode)

    The bucket name carries the *principal*, never the key. It used to be
    f"apikey:{api_key}", which writes the raw credential into the Redis
    keyspace when REDIS_URL is set — where it shows up in KEYS, MONITOR,
    SLOWLOG, any metrics exporter that samples key names, and every snapshot
    taken of that database.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        principal = principal_for(api_key)
        if principal is not None:
            return f"principal:{principal}"
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


# ── Middleware ───────────────────────────────────────────────────────────────


def _iter_routes(routes):
    """Every route, descending into included routers.

    FastAPI 0.139 no longer flattens ``include_router`` into ``app.routes``: it
    appends one ``_IncludedRouter`` per call, holding the real routes on
    ``.original_router``. slowapi's own lookup scans ``app.routes`` flat, found
    no ``/v1`` route, and treats "no route" as exempt, so **no mediation,
    policy or admin route was rate limited at all**. Measured: 8 calls under a
    5/minute limit, all 200. Same nesting as test_api_auth's route walk.
    """
    for route in routes:
        nested = getattr(route, "routes", None)
        if nested is None:
            nested = getattr(getattr(route, "original_router", None), "routes", None)
        if nested is not None and not hasattr(route, "endpoint"):
            yield from _iter_routes(nested)
        else:
            yield route


def find_route_handler(routes, scope):
    from starlette.routing import Match

    handler = None
    for route in _iter_routes(routes):
        match, _ = route.matches(scope)
        if match == Match.FULL and hasattr(route, "endpoint"):
            handler = route.endpoint
    return handler


def build_rate_limit_middleware():
    """SlowAPIMiddleware with a route lookup that sees included routers."""
    from slowapi.middleware import SlowAPIMiddleware, _should_exempt, sync_check_limits

    class RateLimitMiddleware(SlowAPIMiddleware):
        async def dispatch(self, request, call_next):
            limiter = request.app.state.limiter
            if not limiter.enabled:
                return await call_next(request)
            handler = find_route_handler(request.app.routes, request.scope)
            if _should_exempt(limiter, handler):
                return await call_next(request)
            error_response, inject = sync_check_limits(limiter, request, handler, request.app)
            if error_response is not None:
                return error_response
            response = await call_next(request)
            if inject:
                response = limiter._inject_headers(response, request.state.view_rate_limit)
            return response

    return RateLimitMiddleware
