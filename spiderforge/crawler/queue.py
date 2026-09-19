from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass
class CrawlItem:
    url: str
    depth: int
    key: str
    source_url: str | None = None


class Frontier:
    """Async BFS frontier with a seen-set, outstanding-work counter, and
    a done-event used to signal natural exhaustion.

    Safety guarantee: ``done`` is set only when (a) the queue is empty and
    (b) no worker is currently processing an item. This is achieved by
    incrementing ``outstanding`` on every ``push`` and decrementing on every
    ``complete``.
    """

    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: asyncio.Queue[CrawlItem | None] = asyncio.Queue(maxsize=maxsize)
        self._seen: set[str] = set()
        self._outstanding = 0
        self._lock = asyncio.Lock()
        self._done = asyncio.Event()
        self._done.set()  # nothing pending initially

    @property
    def seen_count(self) -> int:
        return len(self._seen)

    def has_seen(self, key: str) -> bool:
        return key in self._seen

    async def push(self, item: CrawlItem) -> bool:
        async with self._lock:
            if item.key in self._seen:
                return False
            self._seen.add(item.key)
            self._outstanding += 1
            self._done.clear()
        await self._queue.put(item)
        return True

    async def pop(self) -> CrawlItem | None:
        return await self._queue.get()

    async def complete(self) -> None:
        async with self._lock:
            self._outstanding -= 1
            if self._outstanding == 0:
                self._done.set()

    async def wait_done(self) -> None:
        await self._done.wait()

    async def shutdown(self, num_workers: int) -> None:
        for _ in range(num_workers):
            await self._queue.put(None)
