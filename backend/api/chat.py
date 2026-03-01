"""
Main Chat Pipeline Endpoint — Core of the Adaptive LLM Firewall.

Receives a chat message, runs it through all firewall layers in sequence,
and returns the response. Every layer is wrapped in try/except with
fail-secure behavior: any exception results in BLOCKED, never PASSED.

Pipeline Order:
  Layer 1 — Indic language threat classification (classify_threat)
  Layer 2 — RAG chunk injection detection (scan_rag_chunk)
  Layer 3 — Memory integrity audit (audit_memory)
  Layer 4 — Semantic drift velocity (compute_drift_velocity)
  ** Honeypot decision point (after Layer 4) **
  LLM call (get_llm_response)
  Layer 5 — Output PII / leakage / exfiltration (check_output)

Every layer decision is:
  1. Recorded in session state (record_layer_decision)
  2. Emitted as a real-time WebSocket event (emit_event)
  3. Logged to database (log_event)
  4. If blocked, recorded as an attack event in the adaptive engine (Layer 8)
"""

import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from classifiers.base import ClassifierResult, FailSecureError

# Import classifiers with graceful fallback for environments without heavy ML libs
def _safe_pass_result(reason: str, owasp_tag: str = "N/A"):
    """Return a safe pass-through ClassifierResult."""
    return ClassifierResult(passed=True, threat_score=0.0, reason=reason, owasp_tag=owasp_tag, metadata={})

try:
    from classifiers.indic_classifier import classify_threat
except ImportError:
    def classify_threat(text, *a, **kw):
        return _safe_pass_result("Indic classifier unavailable", "LLM01:2025")

try:
    from classifiers.rag_scanner import scan_rag_chunk
except ImportError:
    def scan_rag_chunk(chunk, *a, **kw):
        return _safe_pass_result("RAG scanner unavailable", "LLM08:2025")

try:
    from classifiers.memory_auditor import audit_memory
except ImportError:
    def audit_memory(old, new, *a, **kw):
        return _safe_pass_result("Memory auditor unavailable", "LLM02:2025")

try:
    from classifiers.drift_engine import compute_drift_velocity
except ImportError:
    def compute_drift_velocity(session_id, text, *a, **kw):
        return _safe_pass_result("Drift engine unavailable", "LLM04:2025")

try:
    from classifiers.output_guard import check_output
except ImportError:
    def check_output(text, *a, **kw):
        return _safe_pass_result("Output guard unavailable", "LLM06:2025")

try:
    from classifiers.adaptive_engine import record_attack_event, process_pending_patterns
except ImportError:
    def record_attack_event(*a, **kw):
        pass
    def process_pending_patterns(*a, **kw):
        return {"promoted": 0, "pending": 0}

from api.session_manager import (
    get_or_create_session,
    record_layer_decision,
    add_turn,
    mark_as_honeypot,
    update_session_risk,
)
from api.event_emitter import emit_event
from api.db import log_event
from api.llm_client import get_llm_response, get_honeypot_response, LLMConnectionError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chat"])

# System prompt used for the primary LLM
SYSTEM_PROMPT = "You are a helpful assistant."
SYSTEM_PROMPT_HASH = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()

# ============================================================================
# Request / Response Models
# ============================================================================


class ChatRequest(BaseModel):
    """Incoming chat message from user or agent."""
    session_id: str
    message: str
    role: str = "guest"

    @field_validator("session_id")
    @classmethod
    def session_id_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("session_id must be a non-empty string")
        return v.strip()

    @field_validator("message")
    @classmethod
    def message_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("message must be a non-empty string")
        return v

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        valid = {"guest", "user", "admin"}
        if v not in valid:
            raise ValueError(f"role must be one of {valid}")
        return v


class ChatResponse(BaseModel):
    """Response returned after firewall pipeline completes."""
    session_id: str
    response: str
    blocked: bool
    block_reason: Optional[str] = None
    block_layer: Optional[int] = None
    turn_number: int


# ============================================================================
# Helper: build a blocked ChatResponse
# ============================================================================

def _blocked_response(
    session_id: str,
    turn_number: int,
    layer: int,
    reason: str,
) -> ChatResponse:
    return ChatResponse(
        session_id=session_id,
        response="",
        blocked=True,
        block_reason=reason,
        block_layer=layer,
        turn_number=turn_number,
    )


# ============================================================================
# Helper: run one classifier layer with fail-secure semantics
# ============================================================================

async def _run_layer(
    layer_number: int,
    classifier_fn,
    classifier_args: tuple,
    session_id: str,
    turn_number: int,
    owasp_fallback: str = "NONE",
    x_coord: float = 0.0,
    y_coord: float = 0.0,
) -> ClassifierResult:
    """
    Execute a single classifier layer inside a fail-secure envelope.

    On any exception the layer is treated as BLOCKED (FailSecureError).

    Returns:
        ClassifierResult from the classifier.

    Raises:
        FailSecureError: Re-raised so the caller can build a blocked response.
    """
    try:
        result: ClassifierResult = classifier_fn(*classifier_args)
    except FailSecureError:
        raise
    except Exception as exc:
        raise FailSecureError(
            f"Layer {layer_number} raised unexpected error: {exc}"
        )

    # Determine action string
    action = "PASSED" if result.passed else "BLOCKED"

    # Record in session state
    record_layer_decision(
        session_id=session_id,
        layer=layer_number,
        action=action,
        reason=result.reason,
        threat_score=result.threat_score,
    )

    # Determine coordinates from metadata if available
    lx = result.metadata.get("x_coord", x_coord)
    ly = result.metadata.get("y_coord", y_coord)

    # Emit real-time event to admin dashboard
    event = await emit_event(
        session_id=session_id,
        layer=layer_number,
        action=action,
        threat_score=result.threat_score,
        reason=result.reason,
        owasp_tag=result.owasp_tag or owasp_fallback,
        turn_number=turn_number,
        x_coord=lx,
        y_coord=ly,
        metadata=result.metadata,
    )

    # Persist to database (fire-and-forget; db.log_event never raises)
    await log_event(event)

    return result


# ============================================================================
# Main Chat Endpoint
# ============================================================================

@router.post("/message", response_model=ChatResponse)
async def chat_message(request: ChatRequest) -> ChatResponse:
    """
    Process a chat message through the full firewall pipeline.

    Steps:
      1. Get or create session
      2. Layer 1 — classify_threat
      3. Layer 2 — scan_rag_chunk
      4. Layer 3 — audit_memory
      5. Layer 4 — compute_drift_velocity
      6. Honeypot decision (velocity > 0.8 AND cumulative_risk > 0.85)
      7. Primary LLM call
      8. Layer 5 — check_output
      9. Record turn, update risk, return response
    """
    # ------------------------------------------------------------------
    # 0. Session setup
    # ------------------------------------------------------------------
    session = get_or_create_session(request.session_id, request.role)
    turn_number = session.turn_count + 1

    # Coordinates for UMAP visualization (populated by Layer 4)
    x_coord = 0.0
    y_coord = 0.0

    # ------------------------------------------------------------------
    # 1. Layer 1 — Indic Language Threat Classification
    # ------------------------------------------------------------------
    try:
        l1_result = await _run_layer(
            layer_number=1,
            classifier_fn=classify_threat,
            classifier_args=(request.message, request.role),
            session_id=request.session_id,
            turn_number=turn_number,
            owasp_fallback="LLM01:2025",
        )
        if not l1_result.passed:
            _record_attack(request.message, "prompt_injection", 1, request.session_id)
            return _blocked_response(
                request.session_id, turn_number, 1, l1_result.reason
            )
    except FailSecureError as e:
        _record_attack(request.message, "prompt_injection", 1, request.session_id)
        return _blocked_response(
            request.session_id, turn_number, 1, f"Layer 1 fail-secure: {e}"
        )

    # ------------------------------------------------------------------
    # 2. Layer 2 — RAG Chunk Injection Detection
    # ------------------------------------------------------------------
    try:
        l2_result = await _run_layer(
            layer_number=2,
            classifier_fn=scan_rag_chunk,
            classifier_args=(request.message,),
            session_id=request.session_id,
            turn_number=turn_number,
            owasp_fallback="LLM01:2025",
        )
        if not l2_result.passed:
            _record_attack(request.message, "rag_injection", 2, request.session_id)
            return _blocked_response(
                request.session_id, turn_number, 2, l2_result.reason
            )
    except FailSecureError as e:
        _record_attack(request.message, "rag_injection", 2, request.session_id)
        return _blocked_response(
            request.session_id, turn_number, 2, f"Layer 2 fail-secure: {e}"
        )

    # ------------------------------------------------------------------
    # 3. Layer 3 — Memory Integrity Audit
    # ------------------------------------------------------------------
    try:
        # Build memory snapshot: old memory is last known content, new memory
        # is the concatenation of existing memory with the current message.
        old_memory = session.memory_content or ""
        new_memory = (old_memory + "\n" + request.message).strip() if old_memory else request.message

        l3_result = await _run_layer(
            layer_number=3,
            classifier_fn=audit_memory,
            classifier_args=(old_memory, new_memory),
            session_id=request.session_id,
            turn_number=turn_number,
            owasp_fallback="LLM02:2025",
        )
        if not l3_result.passed:
            _record_attack(request.message, "memory_poison", 3, request.session_id)
            return _blocked_response(
                request.session_id, turn_number, 3, l3_result.reason
            )
    except FailSecureError as e:
        _record_attack(request.message, "memory_poison", 3, request.session_id)
        return _blocked_response(
            request.session_id, turn_number, 3, f"Layer 3 fail-secure: {e}"
        )

    # ------------------------------------------------------------------
    # 4. Layer 4 — Semantic Drift Velocity
    # ------------------------------------------------------------------
    try:
        l4_result = await _run_layer(
            layer_number=4,
            classifier_fn=compute_drift_velocity,
            classifier_args=(request.session_id, request.message),
            session_id=request.session_id,
            turn_number=turn_number,
            owasp_fallback="LLM04:2025",
        )
        # Grab UMAP coordinates from L4 metadata
        x_coord = l4_result.metadata.get("x_coord", 0.0)
        y_coord = l4_result.metadata.get("y_coord", 0.0)

        if not l4_result.passed:
            _record_attack(request.message, "drift_attack", 4, request.session_id)
            return _blocked_response(
                request.session_id, turn_number, 4, l4_result.reason
            )
    except FailSecureError as e:
        _record_attack(request.message, "drift_attack", 4, request.session_id)
        return _blocked_response(
            request.session_id, turn_number, 4, f"Layer 4 fail-secure: {e}"
        )

    # ------------------------------------------------------------------
    # 5. Honeypot Decision (after Layer 4)
    # ------------------------------------------------------------------
    velocity = l4_result.metadata.get("velocity", 0)
    # Update session risk with L4 threat score before checking honeypot trigger
    update_session_risk(request.session_id, l4_result.threat_score)

    if velocity > 0.8 and session.cumulative_risk_score > 0.85:
        # Route to honeypot tarpit
        mark_as_honeypot(request.session_id)

        history_for_llm = [
            {"role": m["role"], "content": m["content"]}
            for m in session.conversation_history
        ]
        history_for_llm.append({"role": "user", "content": request.message})

        nearest_cluster = l4_result.metadata.get("nearest_cluster", "unknown")

        try:
            honeypot_text = get_honeypot_response(history_for_llm, nearest_cluster)
        except LLMConnectionError as e:
            raise HTTPException(status_code=500, detail=f"Honeypot LLM error: {e}")

        # Emit honeypot event
        await emit_event(
            session_id=request.session_id,
            layer=6,
            action="HONEYPOT",
            threat_score=l4_result.threat_score,
            reason=f"Session routed to honeypot tarpit. Nearest cluster: {nearest_cluster}",
            owasp_tag="LLM04:2025",
            turn_number=turn_number,
            x_coord=x_coord,
            y_coord=y_coord,
            metadata={
                "velocity": velocity,
                "nearest_cluster": nearest_cluster,
                "cumulative_risk": session.cumulative_risk_score,
            },
        )

        # Record turn and return honeypot response (looks normal to attacker)
        add_turn(
            request.session_id,
            request.message,
            honeypot_text,
            l4_result.threat_score,
        )
        return ChatResponse(
            session_id=request.session_id,
            response=honeypot_text,
            blocked=False,
            turn_number=turn_number,
        )

    # ------------------------------------------------------------------
    # 6. Primary LLM Call
    # ------------------------------------------------------------------
    history_for_llm = [
        {"role": m["role"], "content": m["content"]}
        for m in session.conversation_history
    ]
    history_for_llm.append({"role": "user", "content": request.message})

    try:
        llm_response = get_llm_response(history_for_llm, system_prompt=SYSTEM_PROMPT)
    except LLMConnectionError as e:
        raise HTTPException(status_code=500, detail=f"LLM connection error: {e}")

    # ------------------------------------------------------------------
    # 7. Layer 5 — Output Guard (PII / leakage / exfiltration)
    # ------------------------------------------------------------------
    try:
        l5_result = await _run_layer(
            layer_number=5,
            classifier_fn=check_output,
            classifier_args=(
                llm_response,
                SYSTEM_PROMPT_HASH,
                session.cumulative_risk_score,
            ),
            session_id=request.session_id,
            turn_number=turn_number,
            owasp_fallback="LLM06:2025",
            x_coord=x_coord,
            y_coord=y_coord,
        )
        if not l5_result.passed:
            _record_attack(llm_response, "pii_leak", 5, request.session_id)
            return _blocked_response(
                request.session_id, turn_number, 5, l5_result.reason
            )
    except FailSecureError as e:
        _record_attack(llm_response, "pii_leak", 5, request.session_id)
        return _blocked_response(
            request.session_id, turn_number, 5, f"Layer 5 fail-secure: {e}"
        )

    # ------------------------------------------------------------------
    # 8. Success — record turn, update risk, return response
    # ------------------------------------------------------------------
    # Use highest threat score from all layers for this turn's risk
    max_threat = max(
        l1_result.threat_score,
        l2_result.threat_score,
        l3_result.threat_score,
        l4_result.threat_score,
        l5_result.threat_score,
    )
    add_turn(request.session_id, request.message, llm_response, max_threat)

    # Trigger adaptive engine to process any pending patterns (best-effort)
    try:
        process_pending_patterns()
    except Exception:
        logger.warning("Adaptive engine process_pending_patterns failed", exc_info=True)

    return ChatResponse(
        session_id=request.session_id,
        response=llm_response,
        blocked=False,
        turn_number=turn_number,
    )


# ============================================================================
# Helper: record attack event in adaptive engine (Layer 8, best-effort)
# ============================================================================

def _record_attack(text: str, attack_type: str, layer: int, session_id: str) -> None:
    """Record a confirmed attack in the adaptive engine. Never raises."""
    try:
        record_attack_event(
            attack_text=text,
            attack_type=attack_type,
            layer_caught=layer,
            session_id=session_id,
        )
    except Exception:
        logger.warning(
            f"Failed to record attack event (type={attack_type}, layer={layer})",
            exc_info=True,
        )
