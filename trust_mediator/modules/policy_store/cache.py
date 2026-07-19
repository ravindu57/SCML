"""
§6.8 — Policy Store: hot policy cache.

Redis-backed (with in-memory fallback) cache for the active policy object.
Eliminates repeated DB hits on the hot request path by caching the
deserialized policy dict for a configurable TTL.

Usage:
    cache = PolicyCache()
    policy = await cache.get()
    if policy is None:
        policy = await load_from_db()
        await cache.set(policy)
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_CACHE_KEY = "trust_mediator:active_policy"


class InMemoryPolicyCache:
    """Simple in-process TTL cache (single-process only)."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self._ttl = ttl_seconds
        self._policy: dict[str, Any] | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get(self) -> dict[str, Any] | None:
        async with self._lock:
            if self._policy is not None and time.monotonic() < self._expires_at:
                return self._policy
            return None

    async def set(self, policy: dict[str, Any]) -> None:
        async with self._lock:
            self._policy = policy
            self._expires_at = time.monotonic() + self._ttl
            logger.debug("policy_cache.set", backend="memory", ttl=self._ttl)

    async def invalidate(self) -> None:
        async with self._lock:
            self._policy = None
            self._expires_at = 0.0
            logger.debug("policy_cache.invalidated", backend="memory")


class RedisPolicyCache:
    """Redis-backed policy cache (requires `redis[asyncio]`)."""

    def __init__(self, redis_url: str, ttl_seconds: int = 60) -> None:
        self._redis_url = redis_url
        self._ttl = ttl_seconds
        self._client: Any = None

    async def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                import redis.asyncio as aioredis  # type: ignore[import]
                self._client = aioredis.from_url(self._redis_url, decode_responses=True)
            except Exception as e:
                logger.warning("policy_cache.redis_connect_failed", error=str(e))
                self._client = None
        return self._client

    async def get(self) -> dict[str, Any] | None:
        client = await self._ensure_client()
        if client is None:
            return None
        try:
            raw = await client.get(_CACHE_KEY)
            if raw is None:
                return None
            policy: dict[str, Any] = json.loads(raw)
            logger.debug("policy_cache.hit", backend="redis")
            return policy
        except Exception as e:
            logger.warning("policy_cache.redis_get_error", error=str(e))
            return None

    async def set(self, policy: dict[str, Any]) -> None:
        client = await self._ensure_client()
        if client is None:
            return
        try:
            await client.setex(_CACHE_KEY, self._ttl, json.dumps(policy))
            logger.debug("policy_cache.set", backend="redis", ttl=self._ttl)
        except Exception as e:
            logger.warning("policy_cache.redis_set_error", error=str(e))

    async def invalidate(self) -> None:
        client = await self._ensure_client()
        if client is None:
            return
        try:
            await client.delete(_CACHE_KEY)
            logger.debug("policy_cache.invalidated", backend="redis")
        except Exception as e:
            logger.warning("policy_cache.redis_invalidate_error", error=str(e))


class PolicyCache:
    """
    Facade that selects Redis or in-memory cache at construction time.

    If `redis_url` is provided and reachable, uses Redis (multi-process safe).
    Otherwise falls back to in-memory cache (single-process only).
    """

    def __init__(self, redis_url: str | None = None, ttl_seconds: int = 60) -> None:
        if redis_url:
            self._backend: InMemoryPolicyCache | RedisPolicyCache = RedisPolicyCache(
                redis_url, ttl_seconds
            )
        else:
            self._backend = InMemoryPolicyCache(ttl_seconds)

    async def get(self) -> dict[str, Any] | None:
        return await self._backend.get()

    async def set(self, policy: dict[str, Any]) -> None:
        await self._backend.set(policy)

    async def invalidate(self) -> None:
        await self._backend.invalidate()
