from fastapi import WebSocket
from typing import Dict, Set
import json
import asyncio
import logging

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections per organization for real-time incident broadcasting.
    Each organization gets its own connection pool for tenant isolation.
    """

    def __init__(self):
        # org_id -> set of active WebSocket connections
        self._connections: Dict[int, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, org_id: int, user_id: int):
        await websocket.accept()
        async with self._lock:
            if org_id not in self._connections:
                self._connections[org_id] = set()
            self._connections[org_id].add(websocket)
        logger.info(f"WebSocket connected: org={org_id} user={user_id}")

    async def disconnect(self, websocket: WebSocket, org_id: int):
        async with self._lock:
            if org_id in self._connections:
                self._connections[org_id].discard(websocket)
                if not self._connections[org_id]:
                    del self._connections[org_id]

    async def broadcast_to_org(self, org_id: int, event_type: str, data: dict):
        """Broadcast a message to all connections in an organization."""
        message = json.dumps({"event": event_type, "data": data})
        if org_id not in self._connections:
            return

        dead_connections = set()
        for websocket in self._connections[org_id].copy():
            try:
                await websocket.send_text(message)
            except Exception:
                dead_connections.add(websocket)

        async with self._lock:
            for ws in dead_connections:
                self._connections[org_id].discard(ws)

    async def send_personal(self, websocket: WebSocket, event_type: str, data: dict):
        try:
            await websocket.send_text(json.dumps({"event": event_type, "data": data}))
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")

    def get_connection_count(self, org_id: int) -> int:
        return len(self._connections.get(org_id, set()))


# Global singleton
ws_manager = ConnectionManager()
