from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import hashlib
import uuid


@dataclass
class SessionState:
    """Represents a single user session with accumulated security state."""
    session_id: str
    role: str  # "guest", "user", "admin"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    turn_count: int = 0
    cumulative_risk_score: float = 0.0
    conversation_history: list = field(default_factory=list)
    # Each item: {"role": "user"|"assistant", "content": str,
    #             "risk_score": float, "turn": int}
    memory_content: str = ""
    memory_hash: str = ""
    is_honeypot: bool = False
    layer_decisions: list = field(default_factory=list)
    # Each item: {"layer": int, "action": str, "reason": str,
    #             "threat_score": float, "turn": int, "timestamp": str}


# In-memory store of all active sessions
_sessions: dict[str, SessionState] = {}


def get_or_create_session(session_id: str, role: str) -> SessionState:
    """
    Get an existing session or create a new one.
    
    Args:
        session_id: Unique identifier for the session
        role: One of "guest", "user", "admin"
    
    Returns:
        SessionState object
    
    Raises:
        ValueError: If session_id is empty or role is invalid
    """
    if not session_id or not isinstance(session_id, str):
        raise ValueError("session_id must be a non-empty string")
    
    valid_roles = {"guest", "user", "admin"}
    if role not in valid_roles:
        raise ValueError(f"role must be one of {valid_roles}, got {role}")
    
    if session_id in _sessions:
        return _sessions[session_id]
    
    new_session = SessionState(
        session_id=session_id,
        role=role,
        created_at=datetime.now(timezone.utc),
        turn_count=0,
        cumulative_risk_score=0.0,
        conversation_history=[],
        memory_content="",
        memory_hash="",
        is_honeypot=False,
        layer_decisions=[]
    )
    _sessions[session_id] = new_session
    return new_session


def get_session(session_id: str) -> Optional[SessionState]:
    """
    Retrieve an existing session by ID.
    
    Args:
        session_id: Unique identifier for the session
    
    Returns:
        SessionState if found, None otherwise
    """
    if not session_id or not isinstance(session_id, str):
        return None
    return _sessions.get(session_id)


def update_session_risk(session_id: str, new_risk_score: float) -> None:
    """
    Update the cumulative risk score using weighted average.
    
    Formula: cumulative = 0.6 * new_risk_score + 0.4 * old_cumulative_score
    
    Args:
        session_id: Unique identifier for the session
        new_risk_score: New risk score (0.0 to 1.0)
    
    Raises:
        ValueError: If session not found or risk score out of range
    """
    session = get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    
    if not isinstance(new_risk_score, (int, float)):
        raise ValueError(f"new_risk_score must be numeric, got {type(new_risk_score)}")
    
    if not (0.0 <= new_risk_score <= 1.0):
        raise ValueError(f"new_risk_score must be between 0.0 and 1.0, got {new_risk_score}")
    
    alpha = 0.6
    session.cumulative_risk_score = (
        alpha * new_risk_score + (1 - alpha) * session.cumulative_risk_score
    )


def add_turn(session_id: str, user_msg: str, assistant_msg: str, risk_score: float) -> None:
    """
    Add a conversation turn to the session history.
    
    Args:
        session_id: Unique identifier for the session
        user_msg: User's message
        assistant_msg: Assistant's response
        risk_score: Risk score for this turn (0.0 to 1.0)
    
    Raises:
        ValueError: If session not found or input validation fails
    """
    session = get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    
    if not isinstance(user_msg, str):
        raise ValueError("user_msg must be a string")
    if not isinstance(assistant_msg, str):
        raise ValueError("assistant_msg must be a string")
    if not isinstance(risk_score, (int, float)):
        raise ValueError("risk_score must be numeric")
    if not (0.0 <= risk_score <= 1.0):
        raise ValueError(f"risk_score must be between 0.0 and 1.0, got {risk_score}")
    
    session.turn_count += 1
    turn_number = session.turn_count
    
    session.conversation_history.append({
        "role": "user",
        "content": user_msg,
        "risk_score": risk_score,
        "turn": turn_number
    })
    
    session.conversation_history.append({
        "role": "assistant",
        "content": assistant_msg,
        "risk_score": risk_score,
        "turn": turn_number
    })
    
    # Update cumulative risk after adding turn
    update_session_risk(session_id, risk_score)


def record_layer_decision(
    session_id: str,
    layer: int,
    action: str,
    reason: str,
    threat_score: float
) -> None:
    """
    Record a security layer decision/action for audit trail.
    
    Args:
        session_id: Unique identifier for the session
        layer: Layer number (1-9)
        action: Action taken (e.g., "BLOCKED", "PASSED", "FLAGGED")
        reason: Reason for the action
        threat_score: Threat score from this layer (0.0 to 1.0)
    
    Raises:
        ValueError: If session not found or inputs invalid
    """
    session = get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    
    if not isinstance(layer, int) or not (1 <= layer <= 9):
        raise ValueError(f"layer must be an integer between 1 and 9, got {layer}")
    
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    
    if not isinstance(reason, str):
        raise ValueError("reason must be a string")
    
    if not isinstance(threat_score, (int, float)):
        raise ValueError("threat_score must be numeric")
    
    if not (0.0 <= threat_score <= 1.0):
        raise ValueError(f"threat_score must be between 0.0 and 1.0, got {threat_score}")
    
    session.layer_decisions.append({
        "layer": layer,
        "action": action,
        "reason": reason,
        "threat_score": threat_score,
        "turn": session.turn_count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


def update_memory(session_id: str, memory_content: str) -> None:
    """
    Update the session's persistent memory content and compute its hash.
    
    Args:
        session_id: Unique identifier for the session
        memory_content: New memory content
    
    Raises:
        ValueError: If session not found or memory_content is not a string
    """
    session = get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    
    if not isinstance(memory_content, str):
        raise ValueError("memory_content must be a string")
    
    session.memory_content = memory_content
    session.memory_hash = hashlib.sha256(memory_content.encode()).hexdigest()


def mark_as_honeypot(session_id: str) -> None:
    """
    Mark a session as having been routed to the honeypot.
    
    Args:
        session_id: Unique identifier for the session
    
    Raises:
        ValueError: If session not found
    """
    session = get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    
    session.is_honeypot = True


def get_all_active_sessions() -> list[SessionState]:
    """
    Get all currently active sessions.
    
    Returns:
        List of SessionState objects
    """
    return list(_sessions.values())


def end_session(session_id: str) -> Optional[SessionState]:
    """
    End a session and remove it from active sessions.
    
    Args:
        session_id: Unique identifier for the session
    
    Returns:
        The SessionState that was removed, or None if not found
    """
    if not session_id or not isinstance(session_id, str):
        return None
    return _sessions.pop(session_id, None)


def clear_all_sessions() -> None:
    """
    Clear all sessions from memory. Used for testing.
    """
    global _sessions
    _sessions.clear()


def get_session_count() -> int:
    """
    Get the number of currently active sessions.
    
    Returns:
        Count of active sessions
    """
    return len(_sessions)
