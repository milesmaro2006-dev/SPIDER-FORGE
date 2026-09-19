"""Token-bucket async rate limiter for SafeHttpClient."""

from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    """Token-bucket rate limiter.

    Ensures no more than ``rate`` requests per second are dispatched.
    ``burst`` allows short spikes up to the bucket size (defaults to rate).
    """

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate is None or rate <= 0:
            self._enabled = False
            self._rate = 0.0
            self._burst = 1
        else:
            self._enabled = True
            self._rate = float(rate)
            self._burst = max(1, int(burst if burst and burst > 0 else rate))

        self._tokens = float(self._burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self._enabled:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                wait_for = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait_for)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0

    async def __aenter__(self) -> AsyncRateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        return None
