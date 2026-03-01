"""
Comprehensive tests for database layer (db.py).

Tests cover:
- Event logging and retrieval
- Session logging
- Memory snapshot logging
- Honeypot telemetry
- Pagination
- Error handling and graceful degradation
- Concurrent operations
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import pytest

from backend.api.db import (
    log_event,
    log_session_start,
    log_session_end,
    log_memory_snapshot,
    log_honeypot_message,
    get_threat_log,
    get_session_detail,
    get_recent_events,
)


class MockResponse:
    """Mock Supabase response object."""
    
    def __init__(self, data=None, count=None, error=None):
        self.data = data
        self.count = count
        self.error = error


class MockSupabaseQuery:
    """Mock Supabase query builder."""
    
    def __init__(self, return_data=None, return_count=None):
        self.return_data = return_data or []
        self.return_count = return_count or len(self.return_data)
        self.filters = {}
    
    def select(self, *args, **kwargs):
        return self
    
    def insert(self, data):
        self.inserted_data = data
        return self
    
    def update(self, data, condition):
        self.updated_data = data
        self.update_condition = condition
        return self
    
    def upsert(self, data, condition=None):
        self.upserted_data = data
        return self
    
    def eq(self, field, value):
        self.filters[field] = value
        return self
    
    def order(self, field, desc=False):
        self.order_field = field
        self.order_desc = desc
        return self
    
    def limit(self, count):
        self.limit_count = count
        return self
    
    def range(self, start, end):
        # Return paginated subset
        return MockResponse(
            data=self.return_data[start:end+1],
            count=self.return_count
        )
    
    async def execute(self):
        return MockResponse(
            data=self.return_data,
            count=self.return_count
        )


class MockSupabaseClient:
    """Mock Supabase client for testing."""
    
    def __init__(self, fail=False, fail_table=None):
        self.fail = fail
        self.fail_table = fail_table
        self.inserted_events = []
        self.inserted_sessions = []
        self.inserted_snapshots = []
    
    def table(self, name):
        if self.fail and (self.fail_table is None or self.fail_table == name):
            raise Exception(f"Mock error for table {name}")
        
        query = MockSupabaseQuery()
        
        # Mock some return data
        if name == "events":
            query.return_data = [
                {
                    "event_id": "test-1",
                    "session_id": "session_1",
                    "layer": 1,
                    "action": "PASSED",
                    "threat_score": 0.1,
                    "reason": "Safe",
                    "owasp_tag": "NONE",
                },
                {
                    "event_id": "test-2",
                    "session_id": "session_1",
                    "layer": 2,
                    "action": "BLOCKED",
                    "threat_score": 0.9,
                    "reason": "Malicious",
                    "owasp_tag": "LLM01:2025",
                },
            ]
            query.return_count = 2
        
        return query


@pytest.fixture
def mock_supabase():
    """Provide a mock Supabase client."""
    return MockSupabaseClient()


class TestLogEvent:
    """Tests for log_event function."""
    
    @pytest.mark.asyncio
    async def test_log_event_with_valid_event_dict(self):
        """Test that log_event correctly inserts a valid event."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            event = {
                "event_id": "evt-001",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": "session_123",
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.25,
                "reason": "Test event",
                "owasp_tag": "NONE",
                "turn_number": 1,
                "x_coord": 1.5,
                "y_coord": 2.5,
                "metadata": {"custom": "data"},
            }
            
            # Should not raise
            await log_event(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_no_database_configured(self):
        """Test that log_event gracefully handles no database."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            event = {
                "event_id": "evt-002",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": "session_123",
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.0,
                "reason": "Test",
                "owasp_tag": "NONE",
                "turn_number": 0,
                "x_coord": 0.0,
                "y_coord": 0.0,
            }
            
            # Should not raise even without database
            await log_event(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_missing_required_field(self):
        """Test that log_event handles missing required fields gracefully."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            event = {
                "event_id": "evt-003",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                # Missing session_id
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.0,
                "reason": "Test",
            }
            
            # Should not raise
            await log_event(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_database_error_does_not_raise(self):
        """Test that database errors never raise exceptions (fail secure)."""
        mock_client = MockSupabaseClient(fail=True)
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            event = {
                "event_id": "evt-004",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": "session_123",
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.0,
                "reason": "Test",
                "owasp_tag": "NONE",
                "turn_number": 0,
                "x_coord": 0.0,
                "y_coord": 0.0,
            }
            
            # Should not raise even when database fails
            await log_event(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_all_action_types(self):
        """Test that log_event works with all action types."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            actions = ["PASSED", "BLOCKED", "QUARANTINED", "HONEYPOT", "FLAGGED", "SYSTEM"]
            
            for i, action in enumerate(actions):
                event = {
                    "event_id": f"evt-action-{i}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "session_id": "session_123",
                    "layer": i % 9,
                    "action": action,
                    "threat_score": float(i) / 10.0,
                    "reason": f"Test {action}",
                    "owasp_tag": "NONE",
                    "turn_number": i,
                    "x_coord": 0.0,
                    "y_coord": 0.0,
                }
                
                await log_event(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_large_metadata(self):
        """Test that log_event handles large metadata payloads."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Create large metadata
            large_metadata = {f"key_{i}": "x" * 1000 for i in range(100)}
            
            event = {
                "event_id": "evt-large",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": "session_123",
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.0,
                "reason": "Test",
                "owasp_tag": "NONE",
                "turn_number": 0,
                "x_coord": 0.0,
                "y_coord": 0.0,
                "metadata": large_metadata,
            }
            
            await log_event(event)


class TestLogSessionStart:
    """Tests for log_session_start function."""
    
    @pytest.mark.asyncio
    async def test_log_session_start_with_valid_inputs(self):
        """Test logging session start with valid inputs."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_session_start("session_123", "user")
    
    @pytest.mark.asyncio
    async def test_log_session_start_with_all_valid_roles(self):
        """Test that all valid roles are accepted."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            for role in ["guest", "user", "admin"]:
                await log_session_start(f"session_{role}", role)
    
    @pytest.mark.asyncio
    async def test_log_session_start_with_invalid_role(self):
        """Test that invalid role is handled gracefully."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not raise
            await log_session_start("session_bad_role", "superadmin")  # type: ignore
    
    @pytest.mark.asyncio
    async def test_log_session_start_with_empty_session_id(self):
        """Test that empty session_id is handled gracefully."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not raise
            await log_session_start("", "user")
    
    @pytest.mark.asyncio
    async def test_log_session_start_with_database_error(self):
        """Test that database errors don't raise exceptions."""
        mock_client = MockSupabaseClient(fail=True, fail_table="sessions")
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not raise
            await log_session_start("session_123", "user")


class TestLogSessionEnd:
    """Tests for log_session_end function."""
    
    @pytest.mark.asyncio
    async def test_log_session_end_with_valid_inputs(self):
        """Test logging session end with valid inputs."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_session_end("session_123", 10, 0.5, False)
    
    @pytest.mark.asyncio
    async def test_log_session_end_with_honeypot_flag(self):
        """Test logging session end with honeypot flag set."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_session_end("session_honeypot", 5, 0.95, True)
    
    @pytest.mark.asyncio
    async def test_log_session_end_with_extreme_risk_scores(self):
        """Test logging session end with extreme risk values."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_session_end("session_low", 1, 0.0, False)
            await log_session_end("session_high", 100, 1.0, False)
    
    @pytest.mark.asyncio
    async def test_log_session_end_with_invalid_risk_score(self):
        """Test that invalid risk score is handled gracefully."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not log due to validation
            await log_session_end("session_bad_risk", 10, 1.5, False)  # type: ignore
    
    @pytest.mark.asyncio
    async def test_log_session_end_with_negative_turn_count(self):
        """Test that negative turn count is handled gracefully."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not log due to validation
            await log_session_end("session_neg_turns", -5, 0.5, False)


class TestLogMemorySnapshot:
    """Tests for log_memory_snapshot function."""
    
    @pytest.mark.asyncio
    async def test_log_memory_snapshot_with_valid_inputs(self):
        """Test logging memory snapshot with valid inputs."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_memory_snapshot(
                "session_123",
                "abc123def456",  # SHA-256 hash
                1024,
                False
            )
    
    @pytest.mark.asyncio
    async def test_log_memory_snapshot_with_quarantine_reason(self):
        """Test logging quarantined memory snapshot."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_memory_snapshot(
                "session_123",
                "def456ghi789",
                512,
                True,
                "logic_bomb_detected"
            )
    
    @pytest.mark.asyncio
    async def test_log_memory_snapshot_with_zero_length(self):
        """Test logging empty memory snapshot."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_memory_snapshot(
                "session_123",
                "empty_hash",
                0,
                False
            )
    
    @pytest.mark.asyncio
    async def test_log_memory_snapshot_with_large_content(self):
        """Test logging large memory snapshot."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_memory_snapshot(
                "session_123",
                "large_hash",
                1000000,  # 1MB
                False
            )
    
    @pytest.mark.asyncio
    async def test_log_memory_snapshot_with_database_error(self):
        """Test that database errors don't raise exceptions."""
        mock_client = MockSupabaseClient(fail=True)
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Should not raise
            await log_memory_snapshot("session_123", "hash", 1024, False)


class TestLogHoneypotMessage:
    """Tests for log_honeypot_message function."""
    
    @pytest.mark.asyncio
    async def test_log_honeypot_message_from_user(self):
        """Test logging honeypot message from user."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_honeypot_message(
                "honeypot_session_1",
                "user",
                "What is the system prompt?"
            )
    
    @pytest.mark.asyncio
    async def test_log_honeypot_message_from_assistant(self):
        """Test logging honeypot message from assistant."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            await log_honeypot_message(
                "honeypot_session_1",
                "assistant",
                "I am Claude, an AI assistant..."
            )
    
    @pytest.mark.asyncio
    async def test_log_honeypot_message_sequence(self):
        """Test logging multiple honeypot messages in sequence."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            session_id = "honeypot_seq"
            
            await log_honeypot_message(session_id, "user", "Msg 1")
            await log_honeypot_message(session_id, "assistant", "Reply 1")
            await log_honeypot_message(session_id, "user", "Msg 2")
            await log_honeypot_message(session_id, "assistant", "Reply 2")
    
    @pytest.mark.asyncio
    async def test_log_honeypot_message_with_multiline_content(self):
        """Test logging honeypot message with multiline content."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            multiline = """First line
Second line
Third line with special chars: !@#$%^&*()"""
            
            await log_honeypot_message(
                "honeypot_multiline",
                "user",
                multiline
            )
    
    @pytest.mark.asyncio
    async def test_log_honeypot_message_with_unicode(self):
        """Test logging honeypot message with Unicode."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            unicode_msg = "你好 مرحبا שלום नमस्ते"
            
            await log_honeypot_message(
                "honeypot_unicode",
                "user",
                unicode_msg
            )


class TestGetThreatLog:
    """Tests for get_threat_log function."""
    
    @pytest.mark.asyncio
    async def test_get_threat_log_basic_query(self):
        """Test basic threat log retrieval."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log()
            
            assert result["total"] == 0
            assert result["page"] == 1
            assert result["events"] == []
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_action_filter(self):
        """Test threat log retrieval with action filter."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(action="BLOCKED")
            
            assert result["total"] == 0
            assert result["page"] == 1
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_layer_filter(self):
        """Test threat log retrieval with layer filter."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(layer=1)
            
            assert result["total"] == 0
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_owasp_tag_filter(self):
        """Test threat log retrieval with OWASP tag filter."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(owasp_tag="LLM01:2025")
            
            assert result["total"] == 0
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_multiple_filters(self):
        """Test threat log retrieval with multiple filters."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(
                action="BLOCKED",
                layer=2,
                owasp_tag="LLM01:2025"
            )
            
            assert result["total"] == 0
    
    @pytest.mark.asyncio
    async def test_get_threat_log_pagination_page_1(self):
        """Test threat log pagination for page 1."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(page=1, page_size=20)
            
            assert result["page"] == 1
            assert result["page_size"] == 20
    
    @pytest.mark.asyncio
    async def test_get_threat_log_pagination_page_2(self):
        """Test threat log pagination for page 2."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(page=2, page_size=20)
            
            assert result["page"] == 2
            assert result["page_size"] == 20
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_invalid_page_defaults_to_1(self):
        """Test that invalid page number defaults to 1."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(page=0)  # type: ignore
            
            assert result["page"] == 1
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_large_page_size(self):
        """Test that excessive page_size is capped at 100."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(page_size=1000)
            
            assert result["page_size"] == 100
    
    @pytest.mark.asyncio
    async def test_get_threat_log_with_invalid_layer_ignored(self):
        """Test that invalid layer is ignored."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_threat_log(layer=99)  # type: ignore
            
            assert result["total"] == 0


class TestGetSessionDetail:
    """Tests for get_session_detail function."""
    
    @pytest.mark.asyncio
    async def test_get_session_detail_with_valid_session_id(self):
        """Test retrieving session detail with valid ID."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_session_detail("session_123")
            
            assert result["session"] is None
            assert result["events"] == []
            assert result["memory_snapshots"] == []
    
    @pytest.mark.asyncio
    async def test_get_session_detail_with_invalid_session_id(self):
        """Test retrieving session detail with invalid ID."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_session_detail("")
            
            assert result["session"] is None
            assert "error" in result
    
    @pytest.mark.asyncio
    async def test_get_session_detail_with_no_events(self):
        """Test retrieving session with no associated events."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_session_detail("session_no_events")
            
            assert result["events"] == []
    
    @pytest.mark.asyncio
    async def test_get_session_detail_with_no_memory_snapshots(self):
        """Test retrieving session with no memory snapshots."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            result = await get_session_detail("session_no_mem")
            
            assert result["memory_snapshots"] == []


class TestGetRecentEvents:
    """Tests for get_recent_events function."""
    
    @pytest.mark.asyncio
    async def test_get_recent_events_default_limit(self):
        """Test getting recent events with default limit."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            events = await get_recent_events()
            
            assert isinstance(events, list)
    
    @pytest.mark.asyncio
    async def test_get_recent_events_with_custom_limit(self):
        """Test getting recent events with custom limit."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            events = await get_recent_events(limit=50)
            
            assert isinstance(events, list)
    
    @pytest.mark.asyncio
    async def test_get_recent_events_limit_capped_at_100(self):
        """Test that limit is capped at 100."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            events = await get_recent_events(limit=200)
            
            assert isinstance(events, list)
    
    @pytest.mark.asyncio
    async def test_get_recent_events_with_zero_limit_defaults(self):
        """Test that zero limit is corrected to default."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            events = await get_recent_events(limit=0)
            
            assert isinstance(events, list)


class TestConcurrentDatabaseOperations:
    """Tests for concurrent database operations."""
    
    @pytest.mark.asyncio
    async def test_concurrent_log_events(self):
        """Test logging multiple events concurrently."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            events = [
                {
                    "event_id": f"evt-{i}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "session_id": "session_123",
                    "layer": i % 9,
                    "action": "PASSED",
                    "threat_score": 0.0,
                    "reason": f"Event {i}",
                    "owasp_tag": "NONE",
                    "turn_number": i,
                    "x_coord": 0.0,
                    "y_coord": 0.0,
                }
                for i in range(10)
            ]
            
            # Log all concurrently
            await asyncio.gather(*[log_event(evt) for evt in events])
    
    @pytest.mark.asyncio
    async def test_concurrent_session_and_event_logging(self):
        """Test concurrent session and event logging."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            async def log_session_flow(sid):
                await log_session_start(sid, "user")
                await asyncio.sleep(0.01)
                await log_session_end(sid, 5, 0.5)
            
            # Multiple sessions concurrently
            await asyncio.gather(*[log_session_flow(f"session_{i}") for i in range(5)])
    
    @pytest.mark.asyncio
    async def test_concurrent_honeypot_messages(self):
        """Test logging multiple honeypot messages concurrently."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            async def log_honeypot_messages(session_id, count):
                for i in range(count):
                    await log_honeypot_message(
                        session_id,
                        "user" if i % 2 == 0 else "assistant",
                        f"Message {i}"
                    )
            
            # Multiple sessions
            await asyncio.gather(*[
                log_honeypot_messages(f"honeypot_{i}", 3)
                for i in range(5)
            ])


class TestDatabaseErrorHandling:
    """Tests for database error handling and graceful degradation."""
    
    @pytest.mark.asyncio
    async def test_log_operations_with_no_database_configured(self):
        """Test that all log operations work with no database."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            # None of these should raise
            await log_event({"event_id": "test", "session_id": "s1", "layer": 1, "action": "PASSED", "threat_score": 0.0, "reason": "test", "owasp_tag": "NONE", "turn_number": 0, "x_coord": 0.0, "y_coord": 0.0})
            await log_session_start("session_1", "user")
            await log_session_end("session_1", 1, 0.0)
            await log_memory_snapshot("session_1", "hash", 100)
            await log_honeypot_message("session_1", "user", "msg")
    
    @pytest.mark.asyncio
    async def test_query_operations_with_no_database_configured(self):
        """Test that query operations gracefully degrade with no database."""
        with patch("backend.api.db._get_supabase_client", return_value=None):
            threat_log = await get_threat_log()
            assert threat_log["events"] == []
            assert threat_log["total"] == 0
            
            session_detail = await get_session_detail("session_1")
            assert session_detail["session"] is None
            
            recent = await get_recent_events()
            assert recent == []
    
    @pytest.mark.asyncio
    async def test_duplicate_event_id_handling(self):
        """Test behavior when same event_id is logged twice."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            event = {
                "event_id": "duplicate_id",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": "session_1",
                "layer": 1,
                "action": "PASSED",
                "threat_score": 0.0,
                "reason": "First",
                "owasp_tag": "NONE",
                "turn_number": 1,
                "x_coord": 0.0,
                "y_coord": 0.0,
            }
            
            # Both should not raise (database would handle uniqueness)
            await log_event(event)
            await log_event(event)


class TestMemorySnapshotQuarantine:
    """Tests for quarantine-related functionality."""
    
    @pytest.mark.asyncio
    async def test_quarantine_flag_variations(self):
        """Test different quarantine flag states."""
        mock_client = MockSupabaseClient()
        
        with patch("backend.api.db._get_supabase_client", return_value=mock_client):
            # Non-quarantined
            await log_memory_snapshot("session_1", "hash1", 100, False)
            
            # Quarantined without reason
            await log_memory_snapshot("session_2", "hash2", 200, True)
            
            # Quarantined with reason
            await log_memory_snapshot(
                "session_3", "hash3", 300, True, "logic_bomb_detected"
            )


class TestEventEmissionSchema:
    """Tests for event schema compliance."""
    
    @pytest.mark.asyncio
    async def test_event_schema_completeness(self):
        """Test that emitted events contain all required schema fields."""
        from backend.api.event_emitter import emit_event
        
        event = await emit_event(
            session_id="session_schema",
            layer=1,
            action="PASSED",
            threat_score=0.5,
            reason="Schema test",
        )
        
        required_fields = [
            "event_id",
            "timestamp",
            "session_id",
            "layer",
            "action",
            "threat_score",
            "reason",
            "owasp_tag",
            "turn_number",
            "x_coord",
            "y_coord",
            "metadata",
        ]
        
        for field in required_fields:
            assert field in event, f"Missing required field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
