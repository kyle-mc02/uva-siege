"""WebSocket broadcast hub for live updates (HANDOFF.md: WS push).

Every mutating request, after it commits, calls `hub.notify(dict)`. The hub
fans the message out to all connected operator and /wall clients so graphs and
the TV ticker refresh live. Messages are small change notifications
("something of type X happened"); clients refetch the slices they care about.

Threading: FastAPI runs our sync endpoints and merge in a threadpool, so
`notify` is called off the event loop. It hands the message to the loop with
`call_soon_threadsafe`, making it safe to call from any thread. If no loop is
bound yet (e.g. in unit tests that exercise merge directly), notify is a no-op.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from starlette.websockets import WebSocket


class Hub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    def notify(self, message: dict[str, Any]) -> None:
        """Thread-safe fire-and-forget broadcast. Safe to call with no loop."""
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        loop.call_soon_threadsafe(lambda: loop.create_task(self._broadcast(message)))

    async def _broadcast(self, message: dict[str, Any]) -> None:
        if not self._clients:
            return
        text = json.dumps(message)
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)
