"""WebSocket connection manager for real-time incident notifications."""
import json
import logging
from typing import Dict, Set
from fastapi import WebSocket, HTTPException
from security import verify_token

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections with organization isolation."""

    def __init__(self):
        # Store connections by organization_id
        # Format: {organization_id: {connection_id: websocket}}
        self.active_connections: Dict[int, Dict[str, WebSocket]] = {}
        self._connection_counter = 0

    async def connect(self, websocket: WebSocket, token: str):
        """Connect a new WebSocket client and authenticate."""
        # Accept first — required by WebSocket protocol before any close()
        await websocket.accept()
        try:
            # Verify token
            token_data = verify_token(token)
            if not token_data or not token_data.organization_id:
                await websocket.close(code=1008, reason="Unauthorized")
                raise HTTPException(status_code=401, detail="Invalid token")

            org_id = token_data.organization_id
            user_id = token_data.user_id

            # Initialize organization connections if needed
            if org_id not in self.active_connections:
                self.active_connections[org_id] = {}

            # Generate unique connection ID
            conn_id = f"user_{user_id}_{self._connection_counter}"
            self._connection_counter += 1

            self.active_connections[org_id][conn_id] = websocket

            logger.info(f"WebSocket connected for org {org_id}, user {user_id} (conn_id: {conn_id})")

            return org_id, conn_id

        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            raise

    def disconnect(self, org_id: int, conn_id: str):
        """Disconnect a WebSocket client."""
        if org_id in self.active_connections:
            if conn_id in self.active_connections[org_id]:
                del self.active_connections[org_id][conn_id]
                logger.info(f"WebSocket disconnected for org {org_id} (conn_id: {conn_id})")

            # Clean up empty organization entries
            if not self.active_connections[org_id]:
                del self.active_connections[org_id]

    async def broadcast_to_org(self, org_id: int, event_type: str, data: dict):
        """Broadcast a message to all clients in an organization."""
        if org_id not in self.active_connections:
            return

        message = {
            "event": event_type,
            "data": data,
            "timestamp": str(__import__('datetime').datetime.utcnow().isoformat())
        }

        message_json = json.dumps(message)
        disconnected = []

        for conn_id, connection in self.active_connections[org_id].items():
            try:
                await connection.send_text(message_json)
            except Exception as e:
                logger.warning(f"Error sending message to {conn_id}: {str(e)}")
                disconnected.append(conn_id)

        # Clean up disconnected clients
        for conn_id in disconnected:
            self.disconnect(org_id, conn_id)

    async def send_to_connection(self, org_id: int, conn_id: str, event_type: str, data: dict):
        """Send a message to a specific connection."""
        if org_id not in self.active_connections or conn_id not in self.active_connections[org_id]:
            return

        message = {
            "event": event_type,
            "data": data,
            "timestamp": str(__import__('datetime').datetime.utcnow().isoformat())
        }

        try:
            await self.active_connections[org_id][conn_id].send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending to connection {conn_id}: {str(e)}")
            self.disconnect(org_id, conn_id)


# Global connection manager instance
manager = ConnectionManager()
