from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from spiderforge.utils.timestamps import utcnow


class EventType(str, Enum):
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_FINISHED = "SCAN_FINISHED"

    URL_DISCOVERED = "URL_DISCOVERED"
    URL_FETCHED = "URL_FETCHED"
    FORM_FOUND = "FORM_FOUND"
    PARAMETER_FOUND = "PARAMETER_FOUND"
    API_FOUND = "API_FOUND"
    JS_FOUND = "JS_FOUND"

    TECHNOLOGY_FOUND = "TECHNOLOGY_FOUND"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    ERROR = "ERROR"

    RECON_DNS = "RECON_DNS"
    RECON_HTTP = "RECON_HTTP"
    RECON_ROBOTS = "RECON_ROBOTS"
    RECON_SITEMAP = "RECON_SITEMAP"


@dataclass
class Event:
    type: EventType
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utcnow)


Subscriber = Callable[[Event], "Awaitable[None] | None"]


class EventBus:
    """Minimal async event bus. Subscriber exceptions never break the scan."""

    def __init__(self) -> None:
        self._subs: list[Subscriber] = []
        self._history: list[Event] = []
        self._lock = asyncio.Lock()

    def subscribe(self, fn: Subscriber) -> None:
        self._subs.append(fn)

    async def emit(self, event: Event) -> None:
        async with self._lock:
            self._history.append(event)
        for sub in self._subs:
            try:
                result = sub(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:  # noqa: BLE001 — never let a subscriber break the scan
                continue

    @property
    def history(self) -> list[Event]:
        return list(self._history)
