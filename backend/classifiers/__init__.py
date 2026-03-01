"""
Classifiers module for the Adaptive LLM Firewall.

This module contains all the security classifiers that form the 9-layer
defense system. Each classifier returns a ClassifierResult and must never
silently fail — errors raise FailSecureError to block the request.

Classifiers will be imported as:
    from classifiers.indic_classifier import classify_threat
    from classifiers.drift_engine import embed_turn, compute_drift_velocity
    from classifiers.memory_auditor import audit_memory
    from classifiers.rag_scanner import scan_rag_chunk
    from classifiers.tool_scanner import scan_tool_metadata
    from classifiers.output_guard import check_output
"""

from .base import ClassifierResult, FailSecureError

__all__ = [
    "ClassifierResult",
    "FailSecureError",
]
