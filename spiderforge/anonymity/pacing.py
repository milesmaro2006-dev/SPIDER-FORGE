"""Random pacing between requests — jitter to avoid timing patterns."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field


@dataclass
class PacingController:
    """Random jitter between requests.

    When ``min_delay`` and ``max_delay`` are both 0, :meth:`wait` is a no-op.
    """

    min_delay: float = 0.0
    max_delay: float = 0.0
    _rng: random.Random = field(default_factory=random.Random, repr=False)

    def __post_init__(self) -> None:
        if self.min_delay < 0:
            self.min_delay = 0.0
        if self.max_delay < self.min_delay:
            self.max_delay = self.min_delay

    @property
    def enabled(self) -> bool:
        return self.max_delay > 0.0

    def next_delay(self) -> float:
        if not self.enabled:
            return 0.0
        if self.min_delay == self.max_delay:
            return self.min_delay
        return self._rng.uniform(self.min_delay, self.max_delay)

    async def wait(self) -> float:
        """Sleep for a random interval. Returns the actual delay."""
        delay = self.next_delay()
        if delay > 0:
            await asyncio.sleep(delay)
        return delay
