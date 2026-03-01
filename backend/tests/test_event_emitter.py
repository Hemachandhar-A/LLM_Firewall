"""
Comprehensive tests for event_emitter module.

Tests cover:
- Event schema validation
- Concurrent broadcast to multiple clients
- Dead connection removal
- Edge cases
- Error handling
"""

import asyncio
import json
import uuid
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime
import pytest

from backend.api.event_emitter import (
    emit_event,
    register_admin_connection,
    unregister_admin_connection,
    get_connected_admin_count,
    clear_all_admin_connections,
)


class MockWebSocket:
    """Mock WebSocket for testing."""
    
    def __init__(self, fail_on_send: bool = False, fail_after: int = 0):
        self.sent_messages = []
        self.fail_on_send = fail_on_send
        self.fail_after = fail_after
        self.send_count = 0
    
    async def send_text(self, data: str) -> None:
        """Send text but optionally fail."""
        self.send_count += 1
        if self.fail_on_send and self.send_count > self.fail_after:
            raise Exception("Mock WebSocket disconnected")
        self.sent_messages.append(data)


@pytest.fixture(autouse=True)
def cleanup_connections():
    """Clear all connections before and after each test."""
    clear_all_admin_connections()
    yield
    clear_all_admin_connections()


class TestEventEmitterBasic:
    """Basic event emitter functionality tests."""
    
    @pytest.mark.asyncio
    async def test_emit_event_returns_complete_event_dict(self):
        """Test that emit_event returns a dict with all required fields."""
        event = await emit_event(
            session_id="session_123",
            layer=1,
            action="PASSED",
            threat_score=0.25,
            reason="Test reason",
            owasp_tag="LLM01:2025",
            turn_number=1,
            x_coord=1.5,
            y_coord=2.5,
            metadata={"custom": "data"},
        )
        
        # Assert all required fields are present
        assert "event_id" in event
        assert "timestamp" in event
        assert "session_id" in event
        assert "layer" in event
        assert "action" in event
        assert "threat_score" in event
        assert "reason" in event
        assert "owasp_tag" in event
        assert "turn_number" in event
        assert "x_coord" in event
        assert "y_coord" in event
        assert "metadata" in event
        
        # Assert field values
        assert event["session_id"] == "session_123"
        assert event["layer"] == 1
        assert event["action"] == "PASSED"
        assert event["threat_score"] == 0.25
        assert event["reason"] == "Test reason"
        assert event["owasp_tag"] == "LLM01:2025"
        assert event["turn_number"] == 1
        assert event["x_coord"] == 1.5
        assert event["y_coord"] == 2.5
        assert event["metadata"] == {"custom": "data"}
    
    @pytest.mark.asyncio
    async def test_emit_event_with_no_connected_clients(self):
        """Test that emit_event completes without error when no clients connected."""
        # No clients registered
        assert get_connected_admin_count() == 0
        
        event = await emit_event(
            session_id="session_456",
            layer=2,
            action="BLOCKED",
            threat_score=0.9,
            reason="Malicious input detected",
        )
        
        assert event is not None
        assert event["action"] == "BLOCKED"
    
    @pytest.mark.asyncio
    async def test_event_id_is_unique_across_multiple_calls(self):
        """Test that event_id is unique across 100 sequential calls."""
        event_ids = set()
        
        for i in range(100):
            event = await emit_event(
                session_id=f"session_{i}",
                layer=i % 9,
                action="PASSED",
                threat_score=0.1,
                reason=f"Test {i}",
            )
            
            assert event["event_id"] not in event_ids, f"Duplicate event_id: {event['event_id']}"
            event_ids.add(event["event_id"])
        
        assert len(event_ids) == 100
    
    @pytest.mark.asyncio
    async def test_event_id_is_valid_uuid4(self):
        """Test that event_id is a valid UUID v4."""
        event = await emit_event(
            session_id="session_uuid",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="UUID test",
        )
        
        try:
            parsed_uuid = uuid.UUID(event["event_id"], version=4)
            assert str(parsed_uuid) == event["event_id"]
        except ValueError:
            pytest.fail("event_id is not a valid UUID v4")
    
    @pytest.mark.asyncio
    async def test_timestamp_is_valid_iso8601(self):
        """Test that timestamp is a valid ISO8601 UTC datetime."""
        event = await emit_event(
            session_id="session_ts",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Timestamp test",
        )
        
        try:
            # Try to parse ISO8601 timestamp
            parsed_dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            assert parsed_dt is not None
            # Should end in +00:00 or Z for UTC
            assert event["timestamp"].endswith("+00:00") or "+00:00" in event["timestamp"]
        except ValueError:
            pytest.fail("timestamp is not a valid ISO8601 datetime")


class TestEventEmitterWebSocketIntegration:
    """Tests for WebSocket client integration."""
    
    @pytest.mark.asyncio
    async def test_emit_event_broadcasts_to_connected_client(self):
        """Test that event is broadcast to a connected WebSocket client."""
        mock_ws = MockWebSocket()
        register_admin_connection(mock_ws)
        
        event = await emit_event(
            session_id="session_ws1",
            layer=3,
            action="QUARANTINED",
            threat_score=0.75,
            reason="Suspicious behavior detected",
        )
        
        # Client should have received the event
        assert len(mock_ws.sent_messages) == 1
        
        # Verify message is valid JSON and contains event data
        sent_data = json.loads(mock_ws.sent_messages[0])
        assert sent_data["event_id"] == event["event_id"]
        assert sent_data["session_id"] == "session_ws1"
        assert sent_data["layer"] == 3
    
    @pytest.mark.asyncio
    async def test_emit_event_broadcasts_to_multiple_clients(self):
        """Test that event is broadcast to multiple connected clients."""
        mock_ws1 = MockWebSocket()
        mock_ws2 = MockWebSocket()
        mock_ws3 = MockWebSocket()
        
        register_admin_connection(mock_ws1)
        register_admin_connection(mock_ws2)
        register_admin_connection(mock_ws3)
        
        event = await emit_event(
            session_id="session_multi",
            layer=5,
            action="FLAGGED",
            threat_score=0.5,
            reason="Multi-client test",
        )
        
        # All clients should have received the event
        assert len(mock_ws1.sent_messages) == 1
        assert len(mock_ws2.sent_messages) == 1
        assert len(mock_ws3.sent_messages) == 1
        
        # All should have the same event_id
        for ws in [mock_ws1, mock_ws2, mock_ws3]:
            sent_data = json.loads(ws.sent_messages[0])
            assert sent_data["event_id"] == event["event_id"]
    
    @pytest.mark.asyncio
    async def test_dead_websocket_client_is_removed_on_next_emit(self):
        """Test that a dead connection (raises on send) is removed."""
        mock_ws_alive = MockWebSocket()
        mock_ws_dead = MockWebSocket(fail_on_send=True)
        
        register_admin_connection(mock_ws_alive)
        register_admin_connection(mock_ws_dead)
        
        assert get_connected_admin_count() == 2
        
        # Emit event; dead client will raise
        event = await emit_event(
            session_id="session_dead",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Dead connection test",
        )
        
        # Dead connection should be automatically removed
        assert get_connected_admin_count() == 1
        
        # Alive client should still have received the event
        assert len(mock_ws_alive.sent_messages) == 1
        
        # Dead client should have attempted but failed
        assert mock_ws_dead.send_count == 1
    
    @pytest.mark.asyncio
    async def test_multiple_dead_clients_removed_concurrently(self):
        """Test that multiple dead clients are all removed in one broadcast."""
        mock_ws_alive1 = MockWebSocket()
        mock_ws_alive2 = MockWebSocket()
        mock_ws_dead1 = MockWebSocket(fail_on_send=True)
        mock_ws_dead2 = MockWebSocket(fail_on_send=True)
        
        register_admin_connection(mock_ws_alive1)
        register_admin_connection(mock_ws_dead1)
        register_admin_connection(mock_ws_alive2)
        register_admin_connection(mock_ws_dead2)
        
        assert get_connected_admin_count() == 4
        
        event = await emit_event(
            session_id="session_multi_dead",
            layer=2,
            action="BLOCKED",
            threat_score=0.99,
            reason="Multiple dead clients test",
        )
        
        # Both dead connections should be removed
        assert get_connected_admin_count() == 2
        
        # Both alive clients should have received the event
        assert len(mock_ws_alive1.sent_messages) == 1
        assert len(mock_ws_alive2.sent_messages) == 1
    
    @pytest.mark.asyncio
    async def test_concurrent_connects_and_disconnects(self):
        """Test registration/unregistration during concurrent emits."""
        initial_ws = MockWebSocket()
        register_admin_connection(initial_ws)
        
        # Emit while dynamically adding/removing connections
        async def emit_continuously():
            for i in range(10):
                await emit_event(
                    session_id=f"session_concurrent_{i}",
                    layer=i % 9,
                    action="PASSED",
                    threat_score=0.0,
                    reason=f"Concurrent test {i}",
                )
                await asyncio.sleep(0.01)
        
        async def add_remove_connections():
            for i in range(5):
                ws = MockWebSocket()
                register_admin_connection(ws)
                await asyncio.sleep(0.02)
                unregister_admin_connection(ws)
        
        # Run concurrently
        await asyncio.gather(emit_continuously(), add_remove_connections())
        
        # Initial connection should still be registered and have received all messages
        assert initial_ws in [initial_ws]
        assert len(initial_ws.sent_messages) >= 1


class TestEventEmitterActionTypes:
    """Test all valid action types."""
    
    @pytest.mark.parametrize("action", ["PASSED", "BLOCKED", "QUARANTINED", "HONEYPOT", "FLAGGED", "SYSTEM"])
    @pytest.mark.asyncio
    async def test_all_valid_action_types(self, action: str):
        """Test that all valid action types are accepted."""
        event = await emit_event(
            session_id=f"session_action_{action}",
            layer=1,
            action=action,
            threat_score=0.5,
            reason=f"Testing action: {action}",
        )
        
        assert event["action"] == action
    
    @pytest.mark.asyncio
    async def test_invalid_action_type_raises_value_error(self):
        """Test that invalid action type raises ValueError."""
        with pytest.raises(ValueError, match="action must be one of"):
            await emit_event(
                session_id="session_invalid_action",
                layer=1,
                action="INVALID_ACTION",
                threat_score=0.5,
                reason="Test",
            )


class TestEventEmitterLayers:
    """Test layer handling."""
    
    @pytest.mark.parametrize("layer", list(range(0, 10)))
    @pytest.mark.asyncio
    async def test_all_valid_layers_0_to_9(self, layer: int):
        """Test that all valid layers (0-9) are accepted."""
        event = await emit_event(
            session_id=f"session_layer_{layer}",
            layer=layer,
            action="PASSED",
            threat_score=0.0,
            reason=f"Layer {layer} test",
        )
        
        assert event["layer"] == layer
    
    @pytest.mark.asyncio
    async def test_layer_10_raises_value_error(self):
        """Test that layer 10 is rejected."""
        with pytest.raises(ValueError, match="layer must be an integer between 0 and 9"):
            await emit_event(
                session_id="session_layer_10",
                layer=10,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_negative_layer_raises_value_error(self):
        """Test that negative layer is rejected."""
        with pytest.raises(ValueError):
            await emit_event(
                session_id="session_layer_neg",
                layer=-1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
            )


class TestEventEmitterThreatScores:
    """Test threat score validation."""
    
    @pytest.mark.parametrize("threat_score", [0.0, 0.25, 0.5, 0.75, 1.0])
    @pytest.mark.asyncio
    async def test_valid_threat_scores(self, threat_score: float):
        """Test that valid threat scores are accepted."""
        event = await emit_event(
            session_id=f"session_score_{threat_score}",
            layer=1,
            action="PASSED",
            threat_score=threat_score,
            reason="Score test",
        )
        
        assert event["threat_score"] == threat_score
    
    @pytest.mark.asyncio
    async def test_integer_threat_score_is_converted_to_float(self):
        """Test that integer threat scores are converted to float."""
        event = await emit_event(
            session_id="session_score_int",
            layer=1,
            action="PASSED",
            threat_score=1,  # Integer
            reason="Score test",
        )
        
        assert event["threat_score"] == 1.0
        assert isinstance(event["threat_score"], float)
    
    @pytest.mark.asyncio
    async def test_threat_score_above_1_0_raises_value_error(self):
        """Test that threat_score > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="threat_score must be between 0.0 and 1.0"):
            await emit_event(
                session_id="session_score_over",
                layer=1,
                action="PASSED",
                threat_score=1.1,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_threat_score_below_0_raises_value_error(self):
        """Test that threat_score < 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="threat_score must be between 0.0 and 1.0"):
            await emit_event(
                session_id="session_score_under",
                layer=1,
                action="PASSED",
                threat_score=-0.1,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_non_numeric_threat_score_raises_type_error(self):
        """Test that non-numeric threat_score raises TypeError."""
        with pytest.raises(TypeError, match="threat_score must be a number"):
            await emit_event(
                session_id="session_score_str",
                layer=1,
                action="PASSED",
                threat_score="0.5",  # String
                reason="Test",
            )


class TestEventEmitterInputValidation:
    """Test input validation for all fields."""
    
    @pytest.mark.asyncio
    async def test_empty_session_id_raises_value_error(self):
        """Test that empty session_id is rejected."""
        with pytest.raises(ValueError, match="session_id must be a non-empty string"):
            await emit_event(
                session_id="",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_whitespace_only_session_id_raises_value_error(self):
        """Test that whitespace-only session_id is rejected."""
        with pytest.raises(ValueError):
            await emit_event(
                session_id="   ",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_none_session_id_raises_value_error(self):
        """Test that None session_id is rejected."""
        with pytest.raises(ValueError):
            await emit_event(
                session_id=None,  # type: ignore
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
            )
    
    @pytest.mark.asyncio
    async def test_empty_reason_raises_value_error(self):
        """Test that empty reason is rejected."""
        with pytest.raises(ValueError, match="reason must be a non-empty string"):
            await emit_event(
                session_id="session_reason",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="",
            )
    
    @pytest.mark.asyncio
    async def test_non_string_owasp_tag_raises_value_error(self):
        """Test that non-string owasp_tag is rejected."""
        with pytest.raises(ValueError, match="owasp_tag must be a string"):
            await emit_event(
                session_id="session_owasp",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
                owasp_tag=123,  # type: ignore
            )
    
    @pytest.mark.asyncio
    async def test_non_integer_turn_number_raises_value_error(self):
        """Test that non-integer turn_number is rejected."""
        with pytest.raises(ValueError, match="turn_number must be a non-negative integer"):
            await emit_event(
                session_id="session_turn",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
                turn_number="1",  # type: ignore
            )
    
    @pytest.mark.asyncio
    async def test_negative_turn_number_raises_value_error(self):
        """Test that negative turn_number is rejected."""
        with pytest.raises(ValueError, match="turn_number must be a non-negative integer"):
            await emit_event(
                session_id="session_turn_neg",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
                turn_number=-1,
            )
    
    @pytest.mark.asyncio
    async def test_non_dict_metadata_raises_type_error(self):
        """Test that non-dict metadata is rejected."""
        with pytest.raises(TypeError, match="metadata must be a dict"):
            await emit_event(
                session_id="session_meta",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
                metadata="not a dict",  # type: ignore
            )


class TestEventEmitterMetadata:
    """Test metadata handling."""
    
    @pytest.mark.asyncio
    async def test_event_with_empty_metadata_dict(self):
        """Test that empty metadata dict is handled."""
        event = await emit_event(
            session_id="session_meta_empty",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Empty metadata test",
            metadata={},
        )
        
        assert event["metadata"] == {}
    
    @pytest.mark.asyncio
    async def test_event_with_large_metadata_payload(self):
        """Test that large metadata payloads are handled."""
        large_metadata = {
            f"key_{i}": {"nested": "value" * 100} for i in range(100)
        }
        
        event = await emit_event(
            session_id="session_meta_large",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Large metadata test",
            metadata=large_metadata,
        )
        
        assert len(event["metadata"]) == 100
    
    @pytest.mark.asyncio
    async def test_event_with_complex_nested_metadata(self):
        """Test that complex nested metadata structures are preserved."""
        complex_metadata = {
            "level1": {
                "level2": {
                    "level3": ["a", "b", "c"],
                    "number": 42,
                }
            },
            "list": [1, 2, 3],
        }
        
        event = await emit_event(
            session_id="session_meta_complex",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Complex metadata test",
            metadata=complex_metadata,
        )
        
        assert event["metadata"]["level1"]["level2"]["level3"] == ["a", "b", "c"]
        assert event["metadata"]["list"] == [1, 2, 3]


class TestEventEmitterUnicode:
    """Test Unicode handling in reason and other fields."""
    
    @pytest.mark.asyncio
    async def test_event_with_unicode_reason(self):
        """Test that Unicode characters in reason are preserved."""
        unicode_reason = "Test with émojis 🔒 and spëcial characters: 中文, हिन्दी"
        
        event = await emit_event(
            session_id="session_unicode",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason=unicode_reason,
        )
        
        assert event["reason"] == unicode_reason
    
    @pytest.mark.asyncio
    async def test_event_with_unicode_session_id(self):
        """Test that Unicode in session_id is preserved."""
        unicode_session = "session_中文_हिन्दी"
        
        event = await emit_event(
            session_id=unicode_session,
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Unicode session test",
        )
        
        assert event["session_id"] == unicode_session
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast_with_unicode_reason(self):
        """Test that WebSocket can handle Unicode in broadcast."""
        mock_ws = MockWebSocket()
        register_admin_connection(mock_ws)
        
        unicode_reason = "🔓 Attempt to access system prompt: 中文"
        
        event = await emit_event(
            session_id="session_unicode_ws",
            layer=1,
            action="BLOCKED",
            threat_score=0.95,
            reason=unicode_reason,
        )
        
        # Verify the message was sent and can be decoded
        assert len(mock_ws.sent_messages) == 1
        sent_data = json.loads(mock_ws.sent_messages[0])
        assert sent_data["reason"] == unicode_reason


class TestEventEmitterCoordinates:
    """Test UMAP coordinate handling."""
    
    @pytest.mark.asyncio
    async def test_event_with_zero_coordinates(self):
        """Test default coordinates (0.0, 0.0)."""
        event = await emit_event(
            session_id="session_coords_zero",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Zero coordinates test",
        )
        
        assert event["x_coord"] == 0.0
        assert event["y_coord"] == 0.0
    
    @pytest.mark.asyncio
    async def test_event_with_positive_coordinates(self):
        """Test with positive UMAP coordinates."""
        event = await emit_event(
            session_id="session_coords_pos",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Positive coordinates test",
            x_coord=5.5,
            y_coord=10.2,
        )
        
        assert event["x_coord"] == 5.5
        assert event["y_coord"] == 10.2
    
    @pytest.mark.asyncio
    async def test_event_with_negative_coordinates(self):
        """Test with negative UMAP coordinates (valid for UMAP output)."""
        event = await emit_event(
            session_id="session_coords_neg",
            layer=1,
            action="PASSED",
            threat_score=0.0,
            reason="Negative coordinates test",
            x_coord=-3.5,
            y_coord=-2.1,
        )
        
        assert event["x_coord"] == -3.5
        assert event["y_coord"] == -2.1
    
    @pytest.mark.asyncio
    async def test_non_numeric_x_coord_raises_type_error(self):
        """Test that non-numeric x_coord raises TypeError."""
        with pytest.raises(TypeError, match="x_coord must be a number"):
            await emit_event(
                session_id="session_coords_bad",
                layer=1,
                action="PASSED",
                threat_score=0.0,
                reason="Test",
                x_coord="5.5",  # type: ignore
            )


class TestEventEmitterConcurrency:
    """Test concurrent event emission."""
    
    @pytest.mark.asyncio
    async def test_simultaneous_emits_to_same_client(self):
        """Test that multiple simultaneous emits work correctly."""
        mock_ws = MockWebSocket()
        register_admin_connection(mock_ws)
        
        # Emit 10 events concurrently
        events = await asyncio.gather(*[
            emit_event(
                session_id=f"session_concurrent_{i}",
                layer=i % 9,
                action="PASSED",
                threat_score=0.0,
                reason=f"Concurrent test {i}",
            )
            for i in range(10)
        ])
        
        # All events should be sent to the client
        assert len(mock_ws.sent_messages) == 10
        
        # All event IDs should be unique
        event_ids = [json.loads(msg)["event_id"] for msg in mock_ws.sent_messages]
        assert len(set(event_ids)) == 10
    
    @pytest.mark.asyncio
    async def test_high_volume_concurrent_emits(self):
        """Test handling of high-volume concurrent events."""
        mock_ws1 = MockWebSocket()
        mock_ws2 = MockWebSocket()
        register_admin_connection(mock_ws1)
        register_admin_connection(mock_ws2)
        
        # Emit 50 events rapidly and concurrently
        events = await asyncio.gather(*[
            emit_event(
                session_id=f"session_hv_{i}",
                layer=i % 9,
                action=["PASSED", "BLOCKED", "FLAGGED"][i % 3],
                threat_score=float(i) / 100.0,
                reason=f"High volume test {i}",
            )
            for i in range(50)
        ])
        
        # Both clients should have received all events
        assert len(mock_ws1.sent_messages) == 50
        assert len(mock_ws2.sent_messages) == 50


class TestEventEmitterDefaults:
    """Test default parameter values."""
    
    @pytest.mark.asyncio
    async def test_function_with_minimal_required_parameters(self):
        """Test that function works with only required parameters."""
        event = await emit_event(
            session_id="session_minimal",
            layer=0,
            action="SYSTEM",
            threat_score=0.0,
            reason="Minimal parameters test",
        )
        
        # Check defaults
        assert event["owasp_tag"] == "NONE"
        assert event["turn_number"] == 0
        assert event["x_coord"] == 0.0
        assert event["y_coord"] == 0.0
        assert event["metadata"] == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
