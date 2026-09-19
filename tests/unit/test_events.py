from __future__ import annotations

import asyncio

from spiderforge.core.events import Event, EventBus, EventType


def test_event_bus_history():
    bus = EventBus()

    async def emit():
        await bus.emit(Event(EventType.RECON_DNS, message="a"))
        await bus.emit(Event(EventType.RECON_HTTP, message="b"))

    asyncio.run(emit())
    assert len(bus.history) == 2
    assert bus.history[0].type == EventType.RECON_DNS


def test_subscriber_exception_does_not_break():
    bus = EventBus()
    seen: list[str] = []

    def bad(_: Event) -> None:
        raise RuntimeError("boom")

    def good(ev: Event) -> None:
        seen.append(ev.message)

    bus.subscribe(bad)
    bus.subscribe(good)

    asyncio.run(bus.emit(Event(EventType.ERROR, message="hi")))
    assert seen == ["hi"]