"""AsyncRateLimiter tests."""

from __future__ import annotations

import time

import pytest

from spiderforge.network.rate_limiter import AsyncRateLimiter


async def test_disabled_when_rate_zero():
    """rate=0 disables the limiter entirely (no sleeps)."""
    limiter = AsyncRateLimiter(rate=0)
    t0 = time.monotonic()
    for _ in range(50):
        async with limiter:
            pass
    elapsed = time.monotonic() - t0
    # 50 acquisitions on a disabled limiter must complete in < 100ms
    assert elapsed < 0.1


async def test_enforces_minimum_rate():
    """At 10 rps, 5 requests should take ≥ 400ms."""
    limiter = AsyncRateLimiter(rate=10.0, burst=1)
    t0 = time.monotonic()
    for _ in range(5):
        async with limiter:
            pass
    elapsed = time.monotonic() - t0
    # 5 requests at 10 rps → 4 waits of ~100ms = ~400ms
    assert elapsed >= 0.35, f"Rate limiter too fast: {elapsed:.3f}s"


async def test_burst_allows_initial_batch():
    """burst=5 lets 5 requests through immediately."""
    limiter = AsyncRateLimiter(rate=100.0, burst=5)
    t0 = time.monotonic()
    for _ in range(5):
        async with limiter:
            pass
    elapsed = time.monotonic() - t0
    # Burst window should complete quickly
    assert elapsed < 0.2


async def test_acquire_and_context_manager_equivalent():
    limiter = AsyncRateLimiter(rate=0)
    # acquire() direct call
    await limiter.acquire()
    # Context manager
    async with limiter:
        pass
    # Both should complete without exception