"""
WebSocket endpoints for real-time admin threat dashboard.

The /admin endpoint accepts connections from admin clients and keeps them
alive with ping/pong messaging. Events are broadcast to all connected
admins via the event_emitter module.
"""

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .event_emitter import register_admin_connection, unregister_admin_connection

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/admin")
async def admin_websocket(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for admin clients to receive real-time threat events.
    
    This endpoint:
    1. Accepts the WebSocket connection
    2. Registers the client in the global admin connections set
    3. Keeps alive with periodic ping/pong messages
    4. Unregisters the client on disconnect or error
    
    The client receives JSON-encoded events from the event_emitter module.
    
    Args:
        websocket: FastAPI WebSocket connection
    """
    try:
        # Accept the connection
        await websocket.accept()
        logger.info(f"Admin client connected from {websocket.client}")
        
        # Register in global admin connections
        register_admin_connection(websocket)
        
        # Keep connection alive with periodic ping/pong
        try:
            while True:
                # Receive data from client (or wait for disconnect)
                # We don't expect client to send anything, but this keeps the connection open
                data = await websocket.receive_text()
                logger.debug(f"Received message from admin client: {data}")
        except WebSocketDisconnect:
            logger.info(f"Admin client disconnected from {websocket.client}")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
    finally:
        # Always unregister on disconnect
        unregister_admin_connection(websocket)
        try:
            await websocket.close()
        except Exception:
            pass  # Connection already closed
