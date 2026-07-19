"""
Rate limiters for the tool-call policy engine (FR-PE-05, NFR-SCAL-01).

Two implementations behind one async interface:

  InMemoryRateLimiter — sliding window on deques; correct for a single
      process only. Default when REDIS_URL is unset (dev / tests).

  RedisRateLimiter — sliding window on a Redis sorted set, atomic via a
      pipeline, shared across workers and replicas. Required for any
      deployment running more than one process (uvicorn --workers > 1,
      gateway mode).

Degradation policy: if Redis becomes unreachable mid-flight the Redis
limiter falls back to a local in-memory window for that call and logs
the degradation. Rate limiting keeps enforcing per-process (degraded but
never disabled); the outage is visible in logs/metrics rather than
silently dropping the control.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

import structlog

logger = structlog.get_logger(__name__)


class InMemoryRateLimiter:
    """Sliding-window rate limiter (per-process, per-agent-per-tool)."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    async def is_allowed(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        window = self._windows[key]
        while window and window[0] < now - window_seconds:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True


class RedisRateLimiter:
    """
    Distributed sliding-window limiter on a Redis sorted set.

    Each key holds one member per call, scored by wall-clock time. A single
    pipelined round trip prunes the window, counts it, and records this call.
    The over-limit call is recorded too (score-then-remove would race);
    counting it keeps the check conservative, which is the correct bias for
    a security control.
    """

    _KEY_PREFIX = "tm:ratelimit:"

    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(
            redis_url, encoding="utf-8", decode_responses=True
        )
        self._fallback = InMemoryRateLimiter()

    async def is_allowed(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        redis_key = f"{self._KEY_PREFIX}{key}"
        member = f"{now:.6f}:{id(object())}"
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipe.zadd(redis_key, {member: now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, window_seconds + 1)
            _, _, count, _ = await pipe.execute()
            if count > limit:
                # Remove our own marker so a burst does not extend the block.
                await self._redis.zrem(redis_key, member)
                return False
            return True
        except Exception as e:
            logger.warning(
                "rate_limiter.redis_unavailable_falling_back_local", error=str(e)
            )
            return await self._fallback.is_allowed(key, limit, window_seconds)

    async def close(self) -> None:
        await self._redis.aclose()


def build_rate_limiter(redis_url: str = "") -> InMemoryRateLimiter | RedisRateLimiter:
    """Return the Redis limiter when a URL is configured, else in-memory."""
    if redis_url:
        logger.info("rate_limiter.backend", backend="redis")
        return RedisRateLimiter(redis_url)
    logger.info("rate_limiter.backend", backend="in-memory")
    return InMemoryRateLimiter()
