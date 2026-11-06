from __future__ import annotations

import asyncio
import json

from fastapi import WebSocket

from app.utils.logger import get_logger

logger = get_logger("ctip.ws")


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info("ws client connected (total=%d)", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info("ws client disconnected (total=%d)", len(self._connections))

    async def broadcast(self, payload: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    def broadcast_threadsafe(self, payload: dict, loop: asyncio.AbstractEventLoop) -> None:
        """Called from the (synchronous) scheduler thread to push into the
        async event loop that FastAPI/uvicorn is running."""
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(payload), loop)
        except Exception as exc:  # noqa: BLE001
            logger.warning("broadcast_threadsafe failed: %s", exc)


manager = ConnectionManager()
