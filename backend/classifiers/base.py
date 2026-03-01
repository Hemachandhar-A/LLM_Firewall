"""
Base classes and exceptions for all classifiers in the firewall pipeline.

All classifiers must return ClassifierResult or raise FailSecureError.
Never return None. Never catch exceptions silently.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


class FailSecureError(Exception):
    """
    Exception raised when a classifier encounters an error.
    
    When this is raised, the security pipeline treats it as a BLOCKED request.
    This ensures we "fail secure" — if something goes wrong in the classifier,
    we default to rejecting the request rather than accidentally allowing it.
    """
    pass


@dataclass
class ClassifierResult:
    """
    Result returned by every classifier in the firewall pipeline.
    
    Attributes:
        passed: True if the input passed security checks, False if it failed.
        threat_score: A float between 0.0 (no threat) and 1.0 (definite threat).
        reason: A human-readable explanation of the classification decision.
        owasp_tag: OWASP LLM Top 10 tag for this threat (e.g., "LLM01:2025").
        metadata: Optional dictionary for classifier-specific extra information.
    """
    passed: bool
    threat_score: float
    reason: str
    owasp_tag: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate threat_score is in valid range."""
        if not 0.0 <= self.threat_score <= 1.0:
            raise ValueError(
                f"threat_score must be between 0.0 and 1.0, got {self.threat_score}"
            )
