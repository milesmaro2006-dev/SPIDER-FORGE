"""BFS frontier with URL deduplication and depth limits."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass
class FrontierItem:
    url: str
    depth: int
    source: str = "seed"


class Frontier:
    """Breadth-First Search frontier."""

    def __init__(self, max_urls: int = 500, max_depth: int = 3) -> None:
        self._queue: deque[FrontierItem] = deque()
        self._scheduled: set[str] = set()
        self._popped: set[str] = set()
        self.max_urls = max(1, int(max_urls))
        self.max_depth = max(0, int(max_depth))

    @property
    def scheduled_count(self) -> int:
        return len(self._scheduled)

    @property
    def popped_count(self) -> int:
        return len(self._popped)

    def is_full(self) -> bool:
        return self.scheduled_count >= self.max_urls

    def is_empty(self) -> bool:
        return not self._queue

    def add(self, url: str, depth: int, source: str = "crawl") -> bool:
        if self.is_full():
            return False
        if depth > self.max_depth:
            return False
        if url in self._scheduled:
            return False

        self._scheduled.add(url)
        self._queue.append(FrontierItem(url=url, depth=depth, source=source))
        return True

    def pop(self) -> FrontierItem | None:
        if not self._queue:
            return None
        item = self._queue.popleft()
        self._popped.add(item.url)
        return item

    def __len__(self) -> int:
        return len(self._queue)

    def __bool__(self) -> bool:
        return bool(self._queue)
