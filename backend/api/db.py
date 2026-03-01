"""
Supabase database layer for the Adaptive LLM Firewall.

This module handles all persistence of security events, sessions, memory
snapshots, and honeypot telemetry to Supabase (PostgreSQL + realtime).

Design:
- All write operations are fire-and-forget with exception logging
- Never raise exceptions in critical paths (pipeline must never block)
- All async operations to avoid blocking the event loop
- Centralized Supabase client initialization from environment variables

Required environment variables:
- SUPABASE_URL: Your Supabase project URL
- SUPABASE_ANON_KEY: Your Supabase anonymous (public) API key
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

try:
    from supabase import create_client, Client
except ImportError:
    raise ImportError("supabase library not installed. Run: pip install supabase")

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class SupabaseSettings(BaseSettings):
    """Load Supabase credentials from environment variables."""
    supabase_url: str = ""
    supabase_anon_key: str = ""
    
    class Config:
        # Load from .env file or system environment
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global Supabase client (lazy-initialized)
_supabase_client: Optional[Client] = None


def _get_supabase_client() -> Optional[Client]:
    """
    Get or initialize the global Supabase client.
    
    Returns None if credentials are not configured, allowing graceful degradation.
    """
    global _supabase_client
    
    if _supabase_client is not None:
        return _supabase_client
    
    try:
        settings = SupabaseSettings()
        
        if not settings.supabase_url or not settings.supabase_anon_key:
            logger.warning(
                "Supabase credentials not configured (SUPABASE_URL or SUPABASE_ANON_KEY missing). "
                "Database logging disabled."
            )
            return None
        
        _supabase_client = create_client(settings.supabase_url, settings.supabase_anon_key)
        logger.info("Supabase client initialized successfully")
        return _supabase_client
    
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None


async def log_event(event: dict) -> None:
    """
    Log a security event to the events table.
    
    This is fire-and-forget: failures are logged but never raised.
    This ensures database logging never blocks the security pipeline.
    
    Event dict must contain:
    - event_id (str)
    - timestamp (str, ISO8601)
    - session_id (str)
    - layer (int, 0-9)
    - action (str)
    - threat_score (float, 0.0-1.0)
    - reason (str)
    - owasp_tag (str)
    - turn_number (int)
    - x_coord (float)
    - y_coord (float)
    - metadata (dict)
    
    Args:
        event: Event dictionary following the unified schema
    """
    client = _get_supabase_client()
    if client is None:
        return
    
    try:
        # Ensure all required fields are present
        required = [
            "event_id", "timestamp", "session_id", "layer", "action",
            "threat_score", "reason", "owasp_tag", "turn_number", "x_coord", "y_coord"
        ]
        
        for field in required:
            if field not in event:
                logger.warning(f"Event missing required field: {field}")
                return
        
        # Insert into events table
        response = await asyncio.to_thread(
            client.table("events").insert,
            {
                "event_id": event["event_id"],
                "session_id": event["session_id"],
                "layer": event["layer"],
                "action": event["action"],
                "threat_score": event["threat_score"],
                "reason": event["reason"],
                "owasp_tag": event["owasp_tag"],
                "turn_number": event["turn_number"],
                "x_coord": event["x_coord"],
                "y_coord": event["y_coord"],
                "metadata": event.get("metadata", {}),
                "timestamp": event["timestamp"],
            }
        )
        
        logger.debug(f"Event {event['event_id']} logged to database")
    
    except Exception as e:
        # Log the error but never raise
        logger.error(f"Failed to log event to database: {e}", exc_info=True)


async def log_session_start(session_id: str, role: str) -> None:
    """
    Log the start of a new session.
    
    Args:
        session_id: Unique session identifier
        role: User role ("guest", "user", or "admin")
    """
    client = _get_supabase_client()
    if client is None:
        return
    
    try:
        if not session_id or not isinstance(session_id, str):
            logger.warning("Invalid session_id for log_session_start")
            return
        
        if role not in {"guest", "user", "admin"}:
            logger.warning(f"Invalid role for session: {role}")
            return
        
        await asyncio.to_thread(
            client.table("sessions").insert,
            {
                "session_id": session_id,
                "role": role,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "total_turns": 0,
                "final_risk_score": 0.0,
                "is_honeypot": False,
            }
        )
        
        logger.debug(f"Session {session_id} ({role}) logged to database")
    
    except Exception as e:
        logger.error(f"Failed to log session start: {e}", exc_info=True)


async def log_session_end(
    session_id: str,
    total_turns: int,
    final_risk_score: float,
    is_honeypot: bool = False,
) -> None:
    """
    Update session record with end state.
    
    Args:
        session_id: Unique session identifier
        total_turns: Total number of turns in the session
        final_risk_score: Final aggregated risk score for the session
        is_honeypot: Whether this session was a honeypot activation
    """
    client = _get_supabase_client()
    if client is None:
        return
    
    try:
        if not session_id or not isinstance(session_id, str):
            logger.warning("Invalid session_id for log_session_end")
            return
        
        if not isinstance(total_turns, int) or total_turns < 0:
            logger.warning(f"Invalid total_turns: {total_turns}")
            return
        
        if not isinstance(final_risk_score, (int, float)) or not 0.0 <= final_risk_score <= 1.0:
            logger.warning(f"Invalid final_risk_score: {final_risk_score}")
            return
        
        await asyncio.to_thread(
            client.table("sessions").update,
            {
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "total_turns": total_turns,
                "final_risk_score": final_risk_score,
                "is_honeypot": is_honeypot,
            },
            {"session_id": session_id}
        )
        
        logger.debug(f"Session {session_id} end logged (turns={total_turns}, risk={final_risk_score})")
    
    except Exception as e:
        logger.error(f"Failed to log session end: {e}", exc_info=True)


async def log_memory_snapshot(
    session_id: str,
    content_hash: str,
    content_length: int,
    quarantined: bool = False,
    quarantine_reason: Optional[str] = None,
) -> None:
    """
    Log a memory snapshot with hash and quarantine status.
    
    Args:
        session_id: Unique session identifier
        content_hash: SHA-256 hash of memory content
        content_length: Length of memory content in bytes
        quarantined: Whether this snapshot was quarantined
        quarantine_reason: Reason if quarantined (e.g., "logic_bomb_detected")
    """
    client = _get_supabase_client()
    if client is None:
        return
    
    try:
        if not session_id or not isinstance(session_id, str):
            logger.warning("Invalid session_id for log_memory_snapshot")
            return
        
        if not content_hash or not isinstance(content_hash, str):
            logger.warning("Invalid content_hash")
            return
        
        if not isinstance(content_length, int) or content_length < 0:
            logger.warning(f"Invalid content_length: {content_length}")
            return
        
        await asyncio.to_thread(
            client.table("memory_snapshots").insert,
            {
                "session_id": session_id,
                "snapshot_hash": content_hash,
                "content_length": content_length,
                "quarantined": quarantined,
                "quarantine_reason": quarantine_reason,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        
        logger.debug(f"Memory snapshot logged for session {session_id} (quarantined={quarantined})")
    
    except Exception as e:
        logger.error(f"Failed to log memory snapshot: {e}", exc_info=True)


async def log_honeypot_message(
    session_id: str,
    role: str,
    content: str,
) -> None:
    """
    Append a message to a honeypot session's message log.
    
    Args:
        session_id: Unique honeypot session identifier
        role: Message role ("user" or "assistant")
        content: Message content
    """
    client = _get_supabase_client()
    if client is None:
        return
    
    try:
        if not session_id or not isinstance(session_id, str):
            logger.warning("Invalid session_id for log_honeypot_message")
            return
        
        if role not in {"user", "assistant"}:
            logger.warning(f"Invalid role for honeypot message: {role}")
            return
        
        if not isinstance(content, str):
            logger.warning("Invalid content for honeypot message")
            return
        
        # Fetch existing session to append to messages
        existing = await asyncio.to_thread(
            client.table("honeypot_sessions").select("messages").eq("session_id", session_id).execute
        )
        
        messages = []
        if existing.data and len(existing.data) > 0:
            messages = existing.data[0].get("messages", [])
        
        # Append new message
        messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        
        # Upsert honeypot session
        await asyncio.to_thread(
            client.table("honeypot_sessions").upsert,
            {
                "session_id": session_id,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "messages": messages,
                "total_messages": len(messages),
            },
            {"onConflict": "session_id"}
        )
        
        logger.debug(f"Honeypot message appended to session {session_id} (total={len(messages)})")
    
    except Exception as e:
        logger.error(f"Failed to log honeypot message: {e}", exc_info=True)


async def get_threat_log(
    action: Optional[str] = None,
    layer: Optional[int] = None,
    owasp_tag: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> dict:
    """
    Retrieve threat events with optional filtering and pagination.
    
    Args:
        action: Filter by action (PASSED, BLOCKED, etc.) — None means no filter
        layer: Filter by layer number (0-9) — None means no filter
        owasp_tag: Filter by OWASP tag — None means no filter
        page: Page number (1-indexed)
        page_size: Number of records per page
    
    Returns:
        dict with keys:
        - "total": int (total number of matching records)
        - "page": int (current page number)
        - "page_size": int (records per page)
        - "events": list (page of events)
        - "error": str (if query failed, included but events will be empty)
    """
    # Validate inputs BEFORE checking client
    if not isinstance(page, int) or page < 1:
        page = 1
    
    if not isinstance(page_size, int) or page_size < 1:
        page_size = 20
    elif page_size > 100:
        page_size = 100
    
    if layer is not None and (not isinstance(layer, int) or layer < 0 or layer > 9):
        layer = None
    
    client = _get_supabase_client()
    
    if client is None:
        return {
            "total": 0,
            "page": page,
            "page_size": page_size,
            "events": [],
            "error": "Database not configured",
        }
    
    try:
        # Build query
        query = client.table("events").select("*", count="exact")
        
        if action is not None and isinstance(action, str):
            query = query.eq("action", action)
        
        if layer is not None:
            query = query.eq("layer", layer)
        
        if owasp_tag is not None and isinstance(owasp_tag, str):
            query = query.eq("owasp_tag", owasp_tag)
        
        # Execute with pagination
        start = (page - 1) * page_size
        response = await asyncio.to_thread(
            query.order("timestamp", desc=True).range,
            start,
            start + page_size - 1
        )
        
        # Extract results
        events = response.data or []
        total = response.count or 0
        
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "events": events,
        }
    
    except Exception as e:
        logger.error(f"Failed to retrieve threat log: {e}", exc_info=True)
        return {
            "total": 0,
            "page": page,
            "page_size": page_size,
            "events": [],
            "error": str(e),
        }


async def get_session_detail(session_id: str) -> dict:
    """
    Retrieve complete details for a session including all associated events.
    
    Args:
        session_id: Unique session identifier
    
    Returns:
        dict with keys:
        - "session": dict (session record) or None if not found
        - "events": list (all events for this session)
        - "memory_snapshots": list (all memory snapshots)
        - "error": str (if query failed)
    """
    client = _get_supabase_client()
    
    if client is None:
        return {
            "session": None,
            "events": [],
            "memory_snapshots": [],
            "error": "Database not configured",
        }
    
    try:
        if not session_id or not isinstance(session_id, str):
            return {
                "session": None,
                "events": [],
                "memory_snapshots": [],
                "error": "Invalid session_id",
            }
        
        # Get session record
        session_response = await asyncio.to_thread(
            client.table("sessions").select("*").eq("session_id", session_id).execute
        )
        
        session = session_response.data[0] if session_response.data else None
        
        # Get all events for this session
        events_response = await asyncio.to_thread(
            client.table("events").select("*").eq("session_id", session_id).order("timestamp").execute
        )
        
        events = events_response.data or []
        
        # Get all memory snapshots for this session
        snapshots_response = await asyncio.to_thread(
            client.table("memory_snapshots").select("*").eq("session_id", session_id).order("created_at").execute
        )
        
        snapshots = snapshots_response.data or []
        
        return {
            "session": session,
            "events": events,
            "memory_snapshots": snapshots,
        }
    
    except Exception as e:
        logger.error(f"Failed to retrieve session detail: {e}", exc_info=True)
        return {
            "session": None,
            "events": [],
            "memory_snapshots": [],
            "error": str(e),
        }


async def get_recent_events(limit: int = 20) -> list:
    """
    Retrieve the most recent security events across all sessions.
    
    Args:
        limit: Number of events to return (default 20, max 100)
    
    Returns:
        list: Most recent events, ordered by timestamp descending
    """
    client = _get_supabase_client()
    
    if client is None:
        return []
    
    try:
        # Validate limit
        if not isinstance(limit, int) or limit < 1:
            limit = 20
        if limit > 100:
            limit = 100
        
        response = await asyncio.to_thread(
            client.table("events").select("*").order("timestamp", desc=True).limit(limit).execute
        )
        
        return response.data or []
    
    except Exception as e:
        logger.error(f"Failed to retrieve recent events: {e}", exc_info=True)
        return []
