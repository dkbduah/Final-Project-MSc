"""
SEAS WebSocket Connection Manager.

Manages active WebSocket connections and broadcasts real-time events
to all connected verification dashboard clients.  Events are fired
whenever a submission is received, verified, aggregated, or finalised.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from fastapi import WebSocket
from fastapi.websockets import WebSocketState


class ConnectionManager:
    """
    Thread-safe WebSocket connection manager for SEAS real-time feed.

    Maintains a list of active WebSocket connections and provides
    broadcast functionality for election aggregation events.
    """

    def __init__(self) -> None:
        """Initialise with an empty connection pool."""
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: Incoming WebSocket connection from a client.
        """
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove a WebSocket connection from the active pool.

        Called when a client disconnects or a send error occurs.

        Args:
            websocket: The WebSocket connection to remove.
        """
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, event: str, data: Dict[str, Any]) -> None:
        """
        Broadcast a JSON event to all currently connected clients.

        Stale connections (closed or errored) are removed automatically.
        Failures on individual connections do not interrupt the broadcast
        to remaining healthy connections.

        Args:
            event: Event type string (e.g. "SUBMISSION_RECEIVED").
            data:  Arbitrary JSON-serialisable event payload.
        """
        message = {
            "event": event,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        stale: List[WebSocket] = []

        async with self._lock:
            connections = list(self._connections)

        for websocket in connections:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
            except Exception:
                stale.append(websocket)

        for ws in stale:
            await self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        """Return the number of currently active WebSocket connections."""
        return len(self._connections)


# Singleton connection manager shared across the application
manager = ConnectionManager()
