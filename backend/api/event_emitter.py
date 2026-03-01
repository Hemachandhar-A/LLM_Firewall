"""
Global event emitter for real-time threat intelligence broadcast to admin WebSocket clients.

This module manages the lifecycle of admin WebSocket connections and broadcasts
security events to all connected clients in real-time. All emissions follow the
unified event schema to ensure consistency across the system.

Design:
- Global set of connected WebSocket clients (thread-safe)
- Async emission via asyncio.gather() for concurrent broadcasts
- Dead connections removed silently on send failure
- Never blocks the security pipeline
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Set
from uuid import uuid4

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Global set of all connected admin WebSocket clients
_admin_connections: Set[WebSocket] = set()


def register_admin_connection(websocket: WebSocket) -> None:
    """
    Register a new admin WebSocket connection.
    
    Args:
        websocket: FastAPI WebSocket connection to register
    
    Raises:
        ValueError: If websocket is None
    """
    if websocket is None:
        raise ValueError("websocket cannot be None")
    _admin_connections.add(websocket)
    logger.debug(f"Admin connection registered. Total connections: {len(_admin_connections)}")


def unregister_admin_connection(websocket: WebSocket) -> None:
    """
    Unregister an admin WebSocket connection.
    
    Safe to call even if the connection is not registered.
    
    Args:
        websocket: FastAPI WebSocket connection to unregister
    """
    if websocket is None:
        return
    _admin_connections.discard(websocket)
    logger.debug(f"Admin connection unregistered. Total connections: {len(_admin_connections)}")


async def emit_event(
    session_id: str,
    layer: int,
    action: str,
    threat_score: float,
    reason: str,
    owasp_tag: str = "NONE",
    turn_number: int = 0,
    x_coord: float = 0.0,
    y_coord: float = 0.0,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Build and emit a security event to all connected admin clients.
    
    This function constructs an event following the unified schema and broadcasts
    it to all connected admin WebSocket clients concurrently. Dead connections
    are removed silently without blocking other clients.
    
    Event Schema:
    {
        "event_id": "UUID v4",
        "timestamp": "ISO8601 UTC",
        "session_id": "str",
        "layer": "int (1–9, or 0 for system events)",
        "action": "PASSED | BLOCKED | QUARANTINED | HONEYPOT | FLAGGED | SYSTEM",
        "threat_score": "float 0.0–1.0",
        "reason": "str",
        "owasp_tag": "e.g. LLM01:2025 or NONE",
        "turn_number": "int",
        "x_coord": "float (UMAP x, 0.0 if N/A)",
        "y_coord": "float (UMAP y, 0.0 if N/A)",
        "metadata": "dict"
    }
    
    Args:
        session_id: Unique session identifier (required)
        layer: Layer number (0-9, where 0 is system event)
        action: Action type (PASSED, BLOCKED, QUARANTINED, HONEYPOT, FLAGGED, SYSTEM)
        threat_score: Float between 0.0 and 1.0
        reason: Human-readable explanation
        owasp_tag: OWASP LLM Top 10 tag (default "NONE")
        turn_number: HTTP request count in this session (default 0)
        x_coord: UMAP x coordinate for visualization (default 0.0)
        y_coord: UMAP y coordinate for visualization (default 0.0)
        metadata: Additional classifier-specific data (default empty dict)
    
    Returns:
        dict: The complete event object that was emitted
    
    Raises:
        ValueError: If required fields are missing or invalid
        TypeError: If threat_score is not a float
    """
    # Validate inputs
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")
    
    if not isinstance(layer, int) or layer < 0 or layer > 9:
        raise ValueError("layer must be an integer between 0 and 9")
    
    valid_actions = {"PASSED", "BLOCKED", "QUARANTINED", "HONEYPOT", "FLAGGED", "SYSTEM"}
    if action not in valid_actions:
        raise ValueError(f"action must be one of {valid_actions}, got {action}")
    
    if not isinstance(threat_score, (int, float)):
        raise TypeError(f"threat_score must be a number, got {type(threat_score)}")
    
    if not 0.0 <= threat_score <= 1.0:
        raise ValueError(f"threat_score must be between 0.0 and 1.0, got {threat_score}")
    
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be a non-empty string")
    
    if not isinstance(owasp_tag, str):
        raise ValueError("owasp_tag must be a string")
    
    if not isinstance(turn_number, int) or turn_number < 0:
        raise ValueError("turn_number must be a non-negative integer")
    
    if not isinstance(x_coord, (int, float)):
        raise TypeError("x_coord must be a number")
    
    if not isinstance(y_coord, (int, float)):
        raise TypeError("y_coord must be a number")
    
    if metadata is None:
        metadata = {}
    elif not isinstance(metadata, dict):
        raise TypeError("metadata must be a dict")
    
    # Build event
    event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "layer": layer,
        "action": action,
        "threat_score": float(threat_score),
        "reason": reason,
        "owasp_tag": owasp_tag,
        "turn_number": turn_number,
        "x_coord": float(x_coord),
        "y_coord": float(y_coord),
        "metadata": metadata,
    }
    
    # Broadcast to all connected admin clients concurrently
    if _admin_connections:
        dead_connections = set()
        
        async def send_to_client(ws: WebSocket) -> None:
            """Attempt to send event to a single client."""
            try:
                await ws.send_text(json.dumps(event))
            except Exception as e:
                # Client disconnected or error occurred; mark for removal
                logger.debug(f"Failed to send event to client: {e}")
                dead_connections.add(ws)
        
        # Send concurrently to all clients
        await asyncio.gather(*[send_to_client(ws) for ws in _admin_connections], return_exceptions=True)
        
        # Remove dead connections
        for ws in dead_connections:
            _admin_connections.discard(ws)
    
    logger.info(f"Event emitted: {event['event_id']} (layer={layer}, action={action}, threat_score={threat_score})")
    
    return event


def get_connected_admin_count() -> int:
    """
    Get the current number of connected admin WebSocket clients.
    
    Returns:
        int: Number of connected clients
    """
    return len(_admin_connections)


def clear_all_admin_connections() -> None:
    """
    Clear all registered admin connections. Useful for testing/cleanup.
    """
    _admin_connections.clear()
    logger.debug("All admin connections cleared")
