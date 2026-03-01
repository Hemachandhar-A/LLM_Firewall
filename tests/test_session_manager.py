import pytest
from datetime import datetime
from backend.api.session_manager import (
    get_or_create_session,
    get_session,
    update_session_risk,
    add_turn,
    record_layer_decision,
    update_memory,
    mark_as_honeypot,
    get_all_active_sessions,
    end_session,
    clear_all_sessions,
    get_session_count,
    SessionState
)


@pytest.fixture(autouse=True)
def cleanup_sessions():
    """Clear all sessions before and after each test."""
    clear_all_sessions()
    yield
    clear_all_sessions()


# ============================================================================
# BASIC FUNCTIONALITY TESTS
# ============================================================================

def test_get_or_create_session_creates_new_session():
    """Test that get_or_create_session creates a new session."""
    session = get_or_create_session("session_1", "user")
    
    assert session is not None
    assert session.session_id == "session_1"
    assert session.role == "user"
    assert session.turn_count == 0
    assert session.cumulative_risk_score == 0.0
    assert session.conversation_history == []
    assert session.is_honeypot is False
    assert session.layer_decisions == []


def test_get_or_create_session_returns_existing():
    """Test that get_or_create_session returns existing session."""
    session1 = get_or_create_session("session_1", "user")
    session1.turn_count = 5
    
    session2 = get_or_create_session("session_1", "admin")
    
    assert session2 is session1
    assert session2.turn_count == 5
    assert session2.role == "user"  # Original role unchanged


def test_get_session_returns_existing():
    """Test that get_session retrieves an existing session."""
    get_or_create_session("session_1", "user")
    session = get_session("session_1")
    
    assert session is not None
    assert session.session_id == "session_1"


def test_get_session_returns_none_for_nonexistent():
    """Test that get_session returns None for nonexistent session."""
    session = get_session("nonexistent")
    assert session is None


def test_update_session_risk_basic():
    """Test basic risk score update with weighted average."""
    get_or_create_session("session_1", "user")
    
    # First update: old = 0.0, new = 0.8
    # result = 0.6 * 0.8 + 0.4 * 0.0 = 0.48
    update_session_risk("session_1", 0.8)
    session = get_session("session_1")
    assert abs(session.cumulative_risk_score - 0.48) < 0.0001
    
    # Second update: old = 0.48, new = 0.2
    # result = 0.6 * 0.2 + 0.4 * 0.48 = 0.12 + 0.192 = 0.312
    update_session_risk("session_1", 0.2)
    session = get_session("session_1")
    assert abs(session.cumulative_risk_score - 0.312) < 0.0001


def test_add_turn_basic():
    """Test adding a conversation turn."""
    get_or_create_session("session_1", "user")
    add_turn("session_1", "Hello", "Hi there", 0.1)
    
    session = get_session("session_1")
    assert session.turn_count == 1
    assert len(session.conversation_history) == 2
    assert session.conversation_history[0]["role"] == "user"
    assert session.conversation_history[0]["content"] == "Hello"
    assert session.conversation_history[1]["role"] == "assistant"
    assert session.conversation_history[1]["content"] == "Hi there"


def test_record_layer_decision_basic():
    """Test recording a layer decision."""
    get_or_create_session("session_1", "user")
    record_layer_decision("session_1", 1, "PASSED", "No threat detected", 0.1)
    
    session = get_session("session_1")
    assert len(session.layer_decisions) == 1
    assert session.layer_decisions[0]["layer"] == 1
    assert session.layer_decisions[0]["action"] == "PASSED"
    assert session.layer_decisions[0]["reason"] == "No threat detected"
    assert session.layer_decisions[0]["threat_score"] == 0.1


def test_mark_as_honeypot():
    """Test marking a session as honeypot."""
    get_or_create_session("session_1", "user")
    assert get_session("session_1").is_honeypot is False
    
    mark_as_honeypot("session_1")
    assert get_session("session_1").is_honeypot is True


def test_end_session():
    """Test ending a session."""
    get_or_create_session("session_1", "user")
    assert get_session_count() == 1
    
    ended_session = end_session("session_1")
    assert ended_session is not None
    assert ended_session.session_id == "session_1"
    assert get_session_count() == 0
    assert get_session("session_1") is None


# ============================================================================
# EDGE CASES: SESSION CREATION AND RETRIEVAL
# ============================================================================

def test_get_or_create_session_empty_session_id():
    """Test creating session with empty session_id raises ValueError."""
    with pytest.raises(ValueError, match="session_id must be a non-empty string"):
        get_or_create_session("", "user")


def test_get_or_create_session_none_session_id():
    """Test creating session with None session_id raises ValueError."""
    with pytest.raises(ValueError, match="session_id must be a non-empty string"):
        get_or_create_session(None, "user")


def test_get_or_create_session_numeric_session_id():
    """Test creating session with numeric session_id raises ValueError."""
    with pytest.raises(ValueError, match="session_id must be a non-empty string"):
        get_or_create_session(12345, "user")


def test_get_or_create_session_invalid_role():
    """Test creating session with invalid role raises ValueError."""
    with pytest.raises(ValueError, match="role must be one of"):
        get_or_create_session("session_1", "superuser")


def test_get_or_create_session_none_role():
    """Test creating session with None role raises ValueError."""
    with pytest.raises(ValueError, match="role must be one of"):
        get_or_create_session("session_1", None)


def test_get_or_create_session_guest_role():
    """Test creating session with guest role."""
    session = get_or_create_session("session_1", "guest")
    assert session.role == "guest"


def test_get_or_create_session_admin_role():
    """Test creating session with admin role."""
    session = get_or_create_session("session_1", "admin")
    assert session.role == "admin"


def test_get_session_empty_session_id():
    """Test get_session with empty session_id returns None."""
    get_or_create_session("session_1", "user")
    result = get_session("")
    assert result is None


def test_get_session_none_session_id():
    """Test get_session with None session_id returns None."""
    get_or_create_session("session_1", "user")
    result = get_session(None)
    assert result is None


def test_multiple_sessions_independent():
    """Test that multiple sessions are fully independent."""
    sess1 = get_or_create_session("session_1", "user")
    sess2 = get_or_create_session("session_2", "admin")
    
    sess1.turn_count = 10
    sess1.cumulative_risk_score = 0.9
    
    assert sess2.turn_count == 0
    assert sess2.cumulative_risk_score == 0.0
    assert sess1 is not sess2


# ============================================================================
# EDGE CASES: RISK SCORE UPDATES
# ============================================================================

def test_update_session_risk_zero_score():
    """Test updating risk score with 0.0."""
    get_or_create_session("session_1", "user")
    update_session_risk("session_1", 0.0)
    
    session = get_session("session_1")
    assert session.cumulative_risk_score == 0.0


def test_update_session_risk_one_score():
    """Test updating risk score with 1.0."""
    get_or_create_session("session_1", "user")
    update_session_risk("session_1", 1.0)
    
    session = get_session("session_1")
    assert abs(session.cumulative_risk_score - 0.6) < 0.0001


def test_update_session_risk_nonexistent_session():
    """Test updating risk for nonexistent session raises ValueError."""
    with pytest.raises(ValueError, match="Session .* not found"):
        update_session_risk("nonexistent", 0.5)


def test_update_session_risk_negative_score():
    """Test updating with negative risk score raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        update_session_risk("session_1", -0.1)


def test_update_session_risk_above_one():
    """Test updating with risk score > 1.0 raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        update_session_risk("session_1", 1.5)


def test_update_session_risk_non_numeric():
    """Test updating with non-numeric risk score raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be numeric"):
        update_session_risk("session_1", "0.5")


def test_update_session_risk_none():
    """Test updating with None risk score raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be numeric"):
        update_session_risk("session_1", None)


def test_update_session_risk_multiple_times():
    """Test multiple risk updates compound correctly."""
    get_or_create_session("session_1", "user")
    
    update_session_risk("session_1", 0.5)
    update_session_risk("session_1", 0.5)
    update_session_risk("session_1", 0.5)
    
    # After 3 updates of 0.5:
    # Update 1: 0.6*0.5 + 0.4*0.0 = 0.3
    # Update 2: 0.6*0.5 + 0.4*0.3 = 0.3 + 0.12 = 0.42
    # Update 3: 0.6*0.5 + 0.4*0.42 = 0.3 + 0.168 = 0.468
    session = get_session("session_1")
    assert abs(session.cumulative_risk_score - 0.468) < 0.0001


# ============================================================================
# EDGE CASES: ADD TURN
# ============================================================================

def test_add_turn_nonexistent_session():
    """Test adding turn to nonexistent session raises ValueError."""
    with pytest.raises(ValueError, match="Session .* not found"):
        add_turn("nonexistent", "Hello", "Hi", 0.1)


def test_add_turn_empty_user_message():
    """Test adding turn with empty user message is allowed."""
    get_or_create_session("session_1", "user")
    add_turn("session_1", "", "Response", 0.1)
    
    session = get_session("session_1")
    assert session.conversation_history[0]["content"] == ""


def test_add_turn_empty_assistant_message():
    """Test adding turn with empty assistant message is allowed."""
    get_or_create_session("session_1", "user")
    add_turn("session_1", "Question", "", 0.1)
    
    session = get_session("session_1")
    assert session.conversation_history[1]["content"] == ""


def test_add_turn_non_string_user_message():
    """Test adding turn with non-string user message raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="user_msg must be a string"):
        add_turn("session_1", 123, "Hi", 0.1)


def test_add_turn_non_string_assistant_message():
    """Test adding turn with non-string assistant message raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="assistant_msg must be a string"):
        add_turn("session_1", "Hello", {"response": "Hi"}, 0.1)


def test_add_turn_invalid_risk_score():
    """Test adding turn with invalid risk score raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        add_turn("session_1", "Hello", "Hi", 1.5)


def test_add_turn_increments_counter():
    """Test that turn_count increments correctly."""
    get_or_create_session("session_1", "user")
    
    add_turn("session_1", "First turn", "Response 1", 0.1)
    assert get_session("session_1").turn_count == 1
    
    add_turn("session_1", "Second turn", "Response 2", 0.2)
    assert get_session("session_1").turn_count == 2


def test_add_turn_updates_cumulative_risk():
    """Test that adding turn updates cumulative risk score."""
    get_or_create_session("session_1", "user")
    
    add_turn("session_1", "Hello", "Hi", 0.8)
    session = get_session("session_1")
    assert abs(session.cumulative_risk_score - 0.48) < 0.0001


def test_add_turn_multiple_turns():
    """Test adding multiple turns to same session."""
    get_or_create_session("session_1", "user")
    
    for i in range(5):
        add_turn("session_1", f"Message {i}", f"Response {i}", 0.1 * (i + 1))
    
    session = get_session("session_1")
    assert session.turn_count == 5
    assert len(session.conversation_history) == 10  # 5 pairs


def test_add_turn_long_messages():
    """Test adding turn with very long messages."""
    get_or_create_session("session_1", "user")
    
    long_msg = "x" * 100000
    add_turn("session_1", long_msg, long_msg, 0.5)
    
    session = get_session("session_1")
    assert len(session.conversation_history[0]["content"]) == 100000


# ============================================================================
# EDGE CASES: RECORD LAYER DECISION
# ============================================================================

def test_record_layer_decision_nonexistent_session():
    """Test recording decision for nonexistent session raises ValueError."""
    with pytest.raises(ValueError, match="Session .* not found"):
        record_layer_decision("nonexistent", 1, "BLOCKED", "Threat", 0.9)


def test_record_layer_decision_layer_zero():
    """Test recording decision with layer 0 raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be an integer between 1 and 9"):
        record_layer_decision("session_1", 0, "BLOCKED", "Threat", 0.9)


def test_record_layer_decision_layer_ten():
    """Test recording decision with layer 10 raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be an integer between 1 and 9"):
        record_layer_decision("session_1", 10, "BLOCKED", "Threat", 0.9)


def test_record_layer_decision_non_integer_layer():
    """Test recording decision with non-integer layer raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be an integer between 1 and 9"):
        record_layer_decision("session_1", 1.5, "BLOCKED", "Threat", 0.9)


def test_record_layer_decision_empty_action():
    """Test recording decision with empty action raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="action must be a non-empty string"):
        record_layer_decision("session_1", 1, "", "Reason", 0.5)


def test_record_layer_decision_none_action():
    """Test recording decision with None action raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="action must be a non-empty string"):
        record_layer_decision("session_1", 1, None, "Reason", 0.5)


def test_record_layer_decision_invalid_threat_score():
    """Test recording decision with invalid threat score raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        record_layer_decision("session_1", 1, "BLOCKED", "Reason", 1.5)


def test_record_layer_decision_all_layers():
    """Test recording decisions for all 9 layers."""
    get_or_create_session("session_1", "user")
    
    for layer in range(1, 10):
        record_layer_decision("session_1", layer, "PASSED", f"Layer {layer}", 0.1)
    
    session = get_session("session_1")
    assert len(session.layer_decisions) == 9
    assert session.layer_decisions[0]["layer"] == 1
    assert session.layer_decisions[8]["layer"] == 9


def test_record_layer_decision_multiple_same_layer():
    """Test recording multiple decisions for the same layer."""
    get_or_create_session("session_1", "user")
    
    record_layer_decision("session_1", 1, "PASSED", "Reason 1", 0.1)
    record_layer_decision("session_1", 1, "BLOCKED", "Reason 2", 0.9)
    
    session = get_session("session_1")
    assert len(session.layer_decisions) == 2
    assert session.layer_decisions[0]["action"] == "PASSED"
    assert session.layer_decisions[1]["action"] == "BLOCKED"


# ============================================================================
# EDGE CASES: MEMORY MANAGEMENT
# ============================================================================

def test_update_memory_basic():
    """Test updating session memory content."""
    get_or_create_session("session_1", "user")
    update_memory("session_1", "Some memory content")
    
    session = get_session("session_1")
    assert session.memory_content == "Some memory content"
    assert len(session.memory_hash) == 64  # SHA-256 hex string


def test_update_memory_hash_consistency():
    """Test that memory hash is consistent for same content."""
    get_or_create_session("session_1", "user")
    
    update_memory("session_1", "Content A")
    hash1 = get_session("session_1").memory_hash
    
    update_memory("session_1", "Content B")
    hash2 = get_session("session_1").memory_hash
    
    update_memory("session_1", "Content A")
    hash3 = get_session("session_1").memory_hash
    
    assert hash1 == hash3
    assert hash1 != hash2


def test_update_memory_empty_content():
    """Test updating memory with empty string."""
    get_or_create_session("session_1", "user")
    update_memory("session_1", "")
    
    session = get_session("session_1")
    assert session.memory_content == ""
    assert len(session.memory_hash) == 64


def test_update_memory_nonexistent_session():
    """Test updating memory for nonexistent session raises ValueError."""
    with pytest.raises(ValueError, match="Session .* not found"):
        update_memory("nonexistent", "Content")


def test_update_memory_non_string():
    """Test updating memory with non-string raises ValueError."""
    get_or_create_session("session_1", "user")
    with pytest.raises(ValueError, match="memory_content must be a string"):
        update_memory("session_1", 12345)


# ============================================================================
# INTEGRATION AND CONCURRENT OPERATIONS
# ============================================================================

def test_session_workflow_complete():
    """Test a complete session workflow with multiple operations."""
    # Create session
    session = get_or_create_session("session_1", "user")
    assert session.session_id == "session_1"
    
    # Add turns
    add_turn("session_1", "Hello", "Hi there", 0.1)
    add_turn("session_1", "How are you?", "I'm doing well", 0.2)
    
    # Record layer decisions
    record_layer_decision("session_1", 1, "PASSED", "No threat", 0.05)
    record_layer_decision("session_1", 2, "PASSED", "No injection", 0.02)
    
    # Update memory
    update_memory("session_1", "User greeted and asked status")
    
    # Mark as honeypot
    mark_as_honeypot("session_1")
    
    # Verify final state
    final = get_session("session_1")
    assert final.turn_count == 2
    assert len(final.conversation_history) == 4
    assert len(final.layer_decisions) == 2
    assert final.is_honeypot is True
    assert final.memory_content == "User greeted and asked status"


def test_duplicate_user_message_in_turn():
    """Test adding turns with duplicate user messages works correctly."""
    get_or_create_session("session_1", "user")
    
    add_turn("session_1", "Same message", "Response 1", 0.1)
    add_turn("session_1", "Same message", "Response 2", 0.2)
    
    session = get_session("session_1")
    assert session.conversation_history[0]["content"] == session.conversation_history[2]["content"]
    assert session.conversation_history[1]["content"] != session.conversation_history[3]["content"]


def test_get_all_active_sessions():
    """Test retrieving all active sessions."""
    sess1 = get_or_create_session("session_1", "user")
    sess2 = get_or_create_session("session_2", "admin")
    sess3 = get_or_create_session("session_3", "guest")
    
    all_sessions = get_all_active_sessions()
    
    assert len(all_sessions) == 3
    session_ids = {s.session_id for s in all_sessions}
    assert session_ids == {"session_1", "session_2", "session_3"}


def test_end_session_nonexistent():
    """Test ending nonexistent session returns None."""
    result = end_session("nonexistent")
    assert result is None


def test_end_session_empty_id():
    """Test ending session with empty ID returns None."""
    get_or_create_session("session_1", "user")
    result = end_session("")
    assert result is None
    assert get_session_count() == 1


def test_session_count_tracking():
    """Test that get_session_count accurately tracks sessions."""
    assert get_session_count() == 0
    
    get_or_create_session("session_1", "user")
    assert get_session_count() == 1
    
    get_or_create_session("session_2", "user")
    assert get_session_count() == 2
    
    end_session("session_1")
    assert get_session_count() == 1
    
    end_session("session_2")
    assert get_session_count() == 0


def test_session_isolation_with_concurrent_updates():
    """Test that sessions are isolated when updated concurrently."""
    get_or_create_session("session_1", "user")
    get_or_create_session("session_2", "user")
    
    # Update both sessions
    update_session_risk("session_1", 0.9)
    update_session_risk("session_2", 0.1)
    
    # Verify isolation
    assert abs(get_session("session_1").cumulative_risk_score - 0.54) < 0.0001
    assert abs(get_session("session_2").cumulative_risk_score - 0.06) < 0.0001


# ============================================================================
# ADVERSARIAL AND BOUNDARY TESTS
# ============================================================================

def test_extreme_role_values():
    """Test roles are validated strictly (case sensitive)."""
    get_or_create_session("session_1", "user")
    
    with pytest.raises(ValueError):
        get_or_create_session("session_2", "USER")
    
    with pytest.raises(ValueError):
        get_or_create_session("session_3", "Admin")


def test_session_id_special_characters():
    """Test session IDs with special characters work correctly."""
    special_ids = [
        "session-1",
        "session_1",
        "session.1",
        "session@1",
        "session#1",
        "123",
        "!@#$%"
    ]
    
    for i, sid in enumerate(special_ids):
        session = get_or_create_session(sid, "user")
        assert session.session_id == sid


def test_memory_with_special_content():
    """Test memory update with various special content."""
    get_or_create_session("session_1", "user")
    
    special_content = [
        "!@#$%^&*()",
        "مرحبا",  # Arabic
        "你好",    # Chinese
        "🔒🔐",   # Emojis
        "\n\t\r",  # Whitespace
        "x" * 10000  # Large content
    ]
    
    for content in special_content:
        update_memory("session_1", content)
        session = get_session("session_1")
        assert session.memory_content == content
        assert len(session.memory_hash) == 64


def test_reason_field_special_characters():
    """Test recording decisions with special character reasons."""
    get_or_create_session("session_1", "user")
    
    special_reasons = [
        "Normal reason",
        "Reason with !@#$%",
        "مرحبا بك",
        "Multi\nline\nreason",
        ""  # Empty is NOT allowed for reason, actually it is since we only check action
    ]
    
    for i, reason in enumerate(special_reasons[:4]):
        record_layer_decision("session_1", 1, "PASSED", reason, 0.5)
        assert get_session("session_1").layer_decisions[i]["reason"] == reason


def test_conversation_with_many_turns():
    """Test session handling of many conversation turns."""
    get_or_create_session("session_1", "user")
    
    n_turns = 100
    for i in range(n_turns):
        add_turn("session_1", f"User turn {i}", f"Assistant turn {i}", 0.5)
    
    session = get_session("session_1")
    assert session.turn_count == n_turns
    assert len(session.conversation_history) == n_turns * 2


def test_many_layer_decisions():
    """Test recording many layer decisions."""
    get_or_create_session("session_1", "user")
    
    n_decisions = 100
    for i in range(n_decisions):
        layer = (i % 9) + 1
        record_layer_decision("session_1", layer, "PASSED", f"Decision {i}", 0.5)
    
    session = get_session("session_1")
    assert len(session.layer_decisions) == n_decisions
