"""In-process event bus used for Server-Sent Events."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self.history: list[dict[str, Any]] = []

    def publish(self, kind: str, payload: dict[str, Any] | None = None) -> None:
        event = {"type": kind, "payload": payload or {}}
        self.history.append(event)
        self.history = self.history[-200:]
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self) -> AsyncIterator[str]:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        try:
            yield f"event: hello\ndata: {json.dumps({'type': 'hello'})}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                except TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            self._subscribers.discard(q)


bus = EventBus()
