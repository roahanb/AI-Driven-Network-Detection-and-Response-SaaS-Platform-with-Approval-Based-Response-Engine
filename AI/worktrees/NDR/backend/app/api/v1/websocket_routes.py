from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging

from app.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import decode_token
from app.websocket.manager import ws_manager
from jose import JWTError

router = APIRouter(tags=["WebSocket"])
logger = logging.getLogger(__name__)


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
):
    """
    WebSocket endpoint for real-time incident notifications.
    Connect with: ws://host/ws?token=<JWT_ACCESS_TOKEN>
    """
    # Authenticate the WebSocket connection via token query param
    try:
        payload = decode_token(token)
        user_id = int(payload.get("sub", 0))
        org_id = int(payload.get("org", 0))
        if not user_id or not org_id:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except JWTError:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    # Verify user is still active
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            await websocket.close(code=4001, reason="User not found or inactive")
            return

    await ws_manager.connect(websocket, org_id, user_id)
    logger.info(f"WebSocket connected: user={user_id} org={org_id}")

    try:
        # Send initial connection confirmation
        await ws_manager.send_personal(websocket, "connected", {
            "message": "Real-time feed connected",
            "org_id": org_id,
            "user_id": user_id,
        })

        # Keep connection alive - listen for pings
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await ws_manager.send_personal(websocket, "pong", {})

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: user={user_id}")
    finally:
        await ws_manager.disconnect(websocket, org_id)
