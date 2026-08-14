"""
Unit tests for tool-policy rate limiters (FR-PE-05, NFR-SCAL-01).
"""

from __future__ import annotations

import pytest

from trust_mediator.modules.tool_policy.rate_limiter import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    build_rate_limiter,
)


class TestInMemoryRateLimiter:
    async def test_allows_up_to_limit(self):
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            assert await limiter.is_allowed("agent:tool", limit=5) is True

    async def test_denies_over_limit(self):
        limiter = InMemoryRateLimiter()
        for _ in range(3):
            await limiter.is_allowed("agent:tool", limit=3)
        assert await limiter.is_allowed("agent:tool", limit=3) is False

    async def test_keys_are_independent(self):
        limiter = InMemoryRateLimiter()
        assert await limiter.is_allowed("a:x", limit=1) is True
        assert await limiter.is_allowed("a:x", limit=1) is False
        assert await limiter.is_allowed("b:y", limit=1) is True

    async def test_window_expiry(self):
        limiter = InMemoryRateLimiter()
        assert await limiter.is_allowed("k", limit=1, window_seconds=0) is True
        # window of 0 seconds → previous entry immediately expired
        assert await limiter.is_allowed("k", limit=1, window_seconds=0) is True


class TestBuildRateLimiter:
    def test_empty_url_gives_in_memory(self):
        assert isinstance(build_rate_limiter(""), InMemoryRateLimiter)

    def test_url_gives_redis(self):
        limiter = build_rate_limiter("redis://localhost:6379/0")
        assert isinstance(limiter, RedisRateLimiter)


class TestRedisRateLimiterFallback:
    async def test_falls_back_to_local_when_redis_down(self):
        """Redis unreachable → degrade to per-process window, never disable."""
        # Port 1 is never a live Redis; connect fails inside is_allowed.
        limiter = RedisRateLimiter("redis://127.0.0.1:1/0")
        assert await limiter.is_allowed("k", limit=1) is True
        assert await limiter.is_allowed("k", limit=1) is False
        await limiter.close()


class TestRedisRateLimiterPipeline:
    async def test_sliding_window_against_fake_redis(self):
        """Exercise the ZSET pipeline logic with an in-process fake."""
        fakeredis = pytest.importorskip("fakeredis")
        # Built through the real constructor, then the client is swapped for
        # the fake. from_url is lazy — no connection is attempted — so this
        # keeps whatever else __init__ sets up instead of re-deriving it here
        # and silently drifting when the limiter gains a field.
        limiter = RedisRateLimiter("redis://localhost:6379/0")
        limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

        for _ in range(3):
            assert await limiter.is_allowed("agent:tool", limit=3) is True
        assert await limiter.is_allowed("agent:tool", limit=3) is False
        # Independent key unaffected
        assert await limiter.is_allowed("other:tool", limit=3) is True
