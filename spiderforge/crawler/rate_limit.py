from __future__ import annotations

import asyncio


class RateLimiter:
    """Process-wide rate limiter enforcing a minimum interval between
    request starts. ``rate_per_sec`` and ``delay`` are combined; the
    stricter of the two wins."""

    def __init__(self, rate_per_sec: float = 0.0, delay: float = 0.0) -> None:
        min_interval = 0.0
        if rate_per_sec > 0:
            min_interval = 1.0 / rate_per_sec
        if delay > min_interval:
            min_interval = delay
        self._min_interval = min_interval
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._last + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = loop.time()
