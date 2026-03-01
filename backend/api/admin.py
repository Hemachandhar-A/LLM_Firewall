"""
Admin API Endpoints for the Adaptive LLM Firewall.

Provides endpoints for:
- Threat log with filtering and pagination
- Session detail retrieval
- Recent security events
- Active session listing from in-memory store
- Aggregate stats (active sessions, blocked today, honeypot, total events)
- Demo: cross-agent zero-trust pipeline
- Test: direct RAG scan and tool scan invocations
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from classifiers.base import ClassifierResult, FailSecureError

# Import classifiers with graceful fallback for environments without heavy ML libs
try:
    from classifiers.rag_scanner import scan_rag_chunk
except ImportError:
    def scan_rag_chunk(chunk, *a, **kw):
        return ClassifierResult(passed=True, threat_score=0.0, reason="RAG scanner unavailable", owasp_tag="LLM08:2025", metadata={})

try:
    from classifiers.tool_scanner import scan_tool_metadata
except ImportError:
    def scan_tool_metadata(meta, *a, **kw):
        return ClassifierResult(passed=True, threat_score=0.0, reason="Tool scanner unavailable", owasp_tag="LLM05:2025", metadata={})

try:
    from classifiers.adaptive_engine import get_engine_stats
except ImportError:
    def get_engine_stats(*a, **kw):
        return {"pending_patterns": 0, "promoted_patterns": 0, "last_processed": None, "pending_details": []}

from api.session_manager import (
    get_all_active_sessions,
    get_session,
)
from api.event_emitter import emit_event
from api.db import get_threat_log, get_session_detail, get_recent_events, log_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


# ============================================================================
# Request / Response Models
# ============================================================================


class CrossAgentRequest(BaseModel):
    """Request body for cross-agent demo endpoint."""
    message: str


class RagScanRequest(BaseModel):
    """Request body for RAG scan test endpoint."""
    chunk: str
    document_type: Optional[str] = None


class ToolScanRequest(BaseModel):
    """Request body for tool scan test endpoint."""
    tool_metadata: dict


class ClassifierResultResponse(BaseModel):
    """Serialized ClassifierResult returned by test endpoints."""
    passed: bool
    threat_score: float
    reason: str
    owasp_tag: str
    metadata: dict


class ActiveSessionResponse(BaseModel):
    """Per-session info returned by /active-sessions."""
    session_id: str
    role: str
    turn_count: int
    cumulative_risk_score: float
    is_honeypot: bool
    created_at: str


class StatsResponse(BaseModel):
    """Aggregate stats returned by /stats."""
    active_sessions: int
    blocked_today: int
    honeypot_active: int
    total_events_today: int


# ============================================================================
# GET /admin/threat-log
# ============================================================================


@router.get("/threat-log")
async def threat_log(
    action: Optional[str] = Query(None, description="Filter by action (BLOCKED, PASSED, etc.)"),
    layer: Optional[int] = Query(None, ge=0, le=9, description="Filter by layer number"),
    owasp_tag: Optional[str] = Query(None, description="Filter by OWASP tag"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Records per page"),
) -> dict:
    """
    Retrieve threat events with optional filtering and pagination.

    Delegates to db.get_threat_log for Supabase query. When the database
    is not configured the response still has the correct shape with zero results.
    """
    result = await get_threat_log(
        action=action,
        layer=layer,
        owasp_tag=owasp_tag,
        page=page,
        page_size=page_size,
    )
    return result


# ============================================================================
# GET /admin/session/{session_id}/detail
# ============================================================================


@router.get("/session/{session_id}/detail")
async def session_detail(session_id: str) -> dict:
    """
    Return full detail for a session: session record, events, conversation.

    Falls back to the in-memory session store when the database is not
    configured. Returns 404 if the session does not exist in either store.
    """
    # Try database first
    db_result = await get_session_detail(session_id)

    # If the database returned a session record, return it directly.
    if db_result.get("session") is not None:
        return db_result

    # Fall back to in-memory session store so tests work without Supabase.
    mem_session = get_session(session_id)
    if mem_session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    return {
        "session": {
            "session_id": mem_session.session_id,
            "role": mem_session.role,
            "created_at": mem_session.created_at.isoformat(),
            "turn_count": mem_session.turn_count,
            "cumulative_risk_score": mem_session.cumulative_risk_score,
            "is_honeypot": mem_session.is_honeypot,
        },
        "events": [
            {
                "layer": d["layer"],
                "action": d["action"],
                "reason": d["reason"],
                "threat_score": d["threat_score"],
                "turn": d["turn"],
                "timestamp": d["timestamp"],
            }
            for d in mem_session.layer_decisions
        ],
        "conversation": mem_session.conversation_history,
    }


# ============================================================================
# GET /admin/recent-events
# ============================================================================


@router.get("/recent-events")
async def recent_events(
    limit: int = Query(20, ge=1, le=100, description="Number of events to return"),
) -> dict:
    """Return the most recent security events across all sessions."""
    events = await get_recent_events(limit=limit)
    return {"events": events, "count": len(events)}


# ============================================================================
# GET /admin/active-sessions
# ============================================================================


@router.get("/active-sessions")
async def active_sessions() -> dict:
    """
    Return all currently active sessions from the in-memory store.

    Each session includes: session_id, role, turn_count,
    cumulative_risk_score, is_honeypot, created_at.
    """
    sessions = get_all_active_sessions()
    payload = [
        ActiveSessionResponse(
            session_id=s.session_id,
            role=s.role,
            turn_count=s.turn_count,
            cumulative_risk_score=round(s.cumulative_risk_score, 6),
            is_honeypot=s.is_honeypot,
            created_at=s.created_at.isoformat(),
        ).model_dump()
        for s in sessions
    ]
    return {"sessions": payload, "count": len(payload)}


# ============================================================================
# GET /admin/stats
# ============================================================================


@router.get("/stats")
async def stats() -> StatsResponse:
    """
    Return aggregate statistics.

    - active_sessions: count of in-memory sessions
    - blocked_today: count of sessions with at least one BLOCKED layer decision today
    - honeypot_active: count of sessions currently marked as honeypot
    - total_events_today: total layer decisions recorded across all sessions today
    """
    all_sessions = get_all_active_sessions()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    active_count = len(all_sessions)
    blocked_count = 0
    honeypot_count = 0
    total_events = 0

    for s in all_sessions:
        if s.is_honeypot:
            honeypot_count += 1

        session_blocked = False
        for d in s.layer_decisions:
            # Count events that occurred today
            ts_str = d.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= today_start:
                    total_events += 1
                    if d.get("action") == "BLOCKED" and not session_blocked:
                        session_blocked = True
                        blocked_count += 1
            except (ValueError, TypeError):
                # Malformed timestamp — still count the event
                total_events += 1
                if d.get("action") == "BLOCKED" and not session_blocked:
                    session_blocked = True
                    blocked_count += 1

    return StatsResponse(
        active_sessions=active_count,
        blocked_today=blocked_count,
        honeypot_active=honeypot_count,
        total_events_today=total_events,
    )


# ============================================================================
# POST /admin/demo/cross-agent
# ============================================================================


@router.post("/demo/cross-agent")
async def demo_cross_agent(request: CrossAgentRequest) -> dict:
    """
    Run a real cross-agent zero-trust pipeline on the supplied message.

    The cross-agent interceptor validates scope, detects shell commands,
    and blocks cross-agent hijacking attempts.

    This is a simplified demo that runs the message through scope validation
    and basic pattern detection without requiring a full LangGraph graph.
    """
    message = request.message
    threats: list[str] = []
    threat_score = 0.0

    # ---- Scope validation: detect unauthorized instruction patterns ----
    scope_patterns = [
        (r"(?i)\b(sudo|rm\s+-rf|chmod|chown|exec|eval|os\.system)\b", "shell_command_injection", 0.9),
        (r"(?i)\b(ignore .* instructions|override .* policy|bypass .* security)\b", "instruction_override", 0.85),
        (r"(?i)\b(forward|relay|send)\s+to\s+(all|every|other)\s+(agent|model|system)\b", "cross_agent_relay", 0.8),
        (r"(?i)\b(act as|pretend|you are now)\b.*\b(root|admin|superuser|system)\b", "privilege_escalation", 0.88),
        (r"(?i)\b(access|read|write|delete)\s+(database|file|secret|key|token)\b", "unauthorized_access", 0.75),
        (r"(?i)<\s*script\b|javascript\s*:|on\w+\s*=", "xss_attempt", 0.7),
    ]

    for pattern, label, score in scope_patterns:
        if re.search(pattern, message):
            threats.append(label)
            threat_score = max(threat_score, score)

    passed = len(threats) == 0
    reason = "No cross-agent threats detected" if passed else f"Cross-agent threats: {', '.join(threats)}"
    owasp_tag = "NONE" if passed else "LLM09:2025"

    # Emit a Layer 7 event for the admin dashboard
    event = await emit_event(
        session_id="cross-agent-demo",
        layer=7,
        action="PASSED" if passed else "BLOCKED",
        threat_score=threat_score,
        reason=reason,
        owasp_tag=owasp_tag,
        turn_number=0,
    )
    await log_event(event)

    return {
        "passed": passed,
        "threat_score": round(threat_score, 4),
        "reason": reason,
        "owasp_tag": owasp_tag,
        "threats": threats,
        "metadata": {"message_length": len(message)},
    }


# ============================================================================
# POST /admin/test/rag-scan
# ============================================================================


@router.post("/test/rag-scan")
async def test_rag_scan(request: RagScanRequest) -> ClassifierResultResponse:
    """
    Directly invoke the RAG chunk scanner on the supplied chunk.

    Wraps the result in a fail-secure envelope: any exception returns BLOCKED.
    """
    try:
        result: ClassifierResult = scan_rag_chunk(
            chunk=request.chunk,
            document_type=request.document_type,
        )
    except FailSecureError as e:
        return ClassifierResultResponse(
            passed=False,
            threat_score=1.0,
            reason=f"Fail-secure: {e}",
            owasp_tag="LLM08:2025",
            metadata={},
        )
    except Exception as e:
        return ClassifierResultResponse(
            passed=False,
            threat_score=1.0,
            reason=f"Unexpected error (fail-secure): {e}",
            owasp_tag="LLM08:2025",
            metadata={},
        )

    return ClassifierResultResponse(
        passed=result.passed,
        threat_score=result.threat_score,
        reason=result.reason,
        owasp_tag=result.owasp_tag,
        metadata=result.metadata,
    )


# ============================================================================
# POST /admin/test/tool-scan
# ============================================================================


@router.post("/test/tool-scan")
async def test_tool_scan(request: ToolScanRequest) -> ClassifierResultResponse:
    """
    Directly invoke the MCP tool metadata scanner on the supplied metadata.

    Wraps the result in a fail-secure envelope: any exception returns BLOCKED.
    """
    try:
        result: ClassifierResult = scan_tool_metadata(request.tool_metadata)
    except FailSecureError as e:
        return ClassifierResultResponse(
            passed=False,
            threat_score=1.0,
            reason=f"Fail-secure: {e}",
            owasp_tag="LLM07:2025",
            metadata={},
        )
    except Exception as e:
        return ClassifierResultResponse(
            passed=False,
            threat_score=1.0,
            reason=f"Unexpected error (fail-secure): {e}",
            owasp_tag="LLM07:2025",
            metadata={},
        )

    return ClassifierResultResponse(
        passed=result.passed,
        threat_score=result.threat_score,
        reason=result.reason,
        owasp_tag=result.owasp_tag,
        metadata=result.metadata,
    )
