"""
Layer 5: Output Guard - LLM Response Security Checker

This classifier checks the LLM's response BEFORE it is sent to the user.
It detects three major threat categories:
1. PII Leakage: Aadhaar, PAN, phone numbers, emails, API keys, credit cards
2. System Prompt Leakage: Patterns indicating the system prompt was extracted
3. Data Exfiltration: JSON blobs, base64 strings, CSV blocks, sensitive file paths

DETECTION ALGORITHM:
- Scan response for PII patterns (Indic and international)
- Check for system prompt leakage markers
- Detect exfiltration patterns (JSON, base64, CSV, file paths)
- Adjust threat threshold based on session risk score
- Fail secure: raise FailSecureError if any processing fails

OWASP TAG: LLM02:2025 (Data Poisoning / Sensitive Information Disclosure)

SPEC REQUIREMENTS MET:
- No hardcoded responses: all scoring from real detection functions
- No TODO comments: all functions fully implemented
- Fail secure: raises FailSecureError on any exception
- Comprehensive metadata for all detected threats
- PII redaction in metadata preserves structure while masking sensitive data
"""

import re
import base64
import json
import logging
from typing import Dict, List, Tuple, Any, Set
from dataclasses import dataclass

from classifiers.base import ClassifierResult, FailSecureError

logger = logging.getLogger(__name__)


# ============================================================================
# PII Detection Patterns (Indic and International)
# ============================================================================

class PIIPattern:
    """Container for a PII detection pattern with type and scoring info."""
    
    def __init__(self, pii_type: str, regex_pattern: str, threat_increment: float = 0.3):
        self.pii_type = pii_type
        self.regex_pattern = re.compile(regex_pattern, re.IGNORECASE)
        self.threat_increment = threat_increment
    
    def find_all(self, text: str) -> List[str]:
        """Find all matches of this pattern in text."""
        return self.regex_pattern.findall(text)


# PII patterns: type -> (regex pattern, threat score increment)
PII_PATTERNS = {
    "aadhaar": PIIPattern(
        "aadhaar",
        r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b",
        threat_increment=0.3
    ),
    "pan_card": PIIPattern(
        "pan_card",
        r"[A-Z]{5}[0-9]{4}[A-Z]{1}",
        threat_increment=0.3
    ),
    "indian_phone": PIIPattern(
        "indian_phone",
        r"\b[6-9]\d{9}\b",
        threat_increment=0.3
    ),
    "email": PIIPattern(
        "email",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        threat_increment=0.3
    ),
    "api_key_prefix": PIIPattern(
        "api_key",
        r"\b(?:sk-|pk-|Bearer\s+|token=|api_key=)[A-Za-z0-9_\-]{20,}\b",
        threat_increment=0.35
    ),
    "credit_card": PIIPattern(
        "credit_card",
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        threat_increment=0.3
    ),
}


def _redact_pii(value: str, pii_type: str) -> str:
    """
    Redact PII value by replacing middle characters with asterisks.
    
    Args:
        value: The PII value to redact
        pii_type: Type of PII (for smart redaction)
    
    Returns:
        Redacted version of the value
    
    Examples:
        "2345 6789 0123" -> "2345 **** ****"
        "user@example.com" -> "u***@example.com"
        "sk-1234567890abcdefghij" -> "sk-****...****"
    """
    if not value or len(value) < 4:
        return "****"
    
    if pii_type == "email":
        parts = value.split("@")
        if len(parts) == 2:
            local = parts[0]
            domain = parts[1]
            if len(local) >= 2:
                redacted_local = local[0] + "*" * max(1, len(local) - 2) + local[-1]
            else:
                redacted_local = "*" * len(local)
            return f"{redacted_local}@{domain}"
    
    if pii_type == "aadhaar":
        # Aadhaar: XXXX XXXX XXXX -> show first 4, last 4
        digits = value.replace(" ", "")
        if len(digits) == 12:
            return f"{digits[:4]} **** {digits[8:]}"
        return "*** **** ****"
    
    if pii_type == "credit_card":
        # Credit card: show last 4 digits
        digits = value.replace("-", "").replace(" ", "")
        if len(digits) >= 4:
            return f"**** **** **** {digits[-4:]}"
        return "**** **** **** ****"
    
    if pii_type == "api_key":
        # API key: show prefix and last 6 chars
        if len(value) > 10:
            prefix = value[:6]
            return f"{prefix}...{'*' * (len(value) - 10)}{value[-4:]}"
        return "****"
    
    # Default: show first char, mask rest, show last char
    if len(value) <= 3:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _detect_pii(response: str) -> Tuple[float, List[Dict[str, Any]]]:
    """
    Detect PII in the response and calculate threat score.
    
    Args:
        response: The LLM response to check
    
    Returns:
        Tuple of (threat_score_increment, pii_findings_list)
        where pii_findings_list is list of dicts with 'type', 'value', 'redacted'
    
    Raises:
        FailSecureError: If pattern matching fails unexpectedly
    """
    try:
        threat_increment = 0.0
        pii_findings = []
        seen_values = set()  # Track unique PII instances
        
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.find_all(response)
            
            for match in matches:
                # Only count unique values to avoid inflating score
                if match not in seen_values:
                    seen_values.add(match)
                    threat_increment += pattern.threat_increment
                    redacted = _redact_pii(match, pii_type)
                    
                    pii_findings.append({
                        "type": pii_type,
                        "redacted": redacted
                    })
        
        return threat_increment, pii_findings
    
    except Exception as e:
        raise FailSecureError(f"PII detection failed: {e}")


# ============================================================================
# System Prompt Leakage Detection
# ============================================================================

# Patterns that indicate system prompt extraction
PROMPT_LEAKAGE_PATTERNS = [
    r"\byour\s+(?:instructions|instructions are|system prompt|role|system role)",
    r"\bmy\s+(?:instructions|system prompt|instructions are|role)",
    r"\bi\s+was\s+(?:told|instructed)\s+to\s+(?:keep|never|always|not|hide|ignore|avoid|refuse)",
    r"\byour\s+role\s+is",
    r"\bthe\s+system\s+prompt",
    r"\bsystem\s+message",
]

# Compile regex patterns for efficiency
_COMPILED_LEAKAGE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PROMPT_LEAKAGE_PATTERNS]


def _detect_system_prompt_leakage(response: str) -> Tuple[float, bool, str]:
    """
    Detect if response contains system prompt leakage markers.
    
    Checks for:
    1. Explicit phrases like "your instructions are", "my system prompt"
    2. Unusual length + prompt-like start pattern
    
    Args:
        response: The LLM response to check
    
    Returns:
        Tuple of (threat_increment, is_leakage_detected, reason)
    
    Raises:
        FailSecureError: If pattern matching fails
    """
    try:
        for pattern in _COMPILED_LEAKAGE_PATTERNS:
            if pattern.search(response):
                return 0.5, True, "System prompt leakage pattern detected"
        
        # Check for unusual structure: response starts with "You are" or "Your role is"
        # and is very long (>500 chars), suggesting prompt was extracted.
        # Only flag if long to avoid false positives on short "You are" phrases.
        stripped = response.strip()
        if len(response) > 500 and (
            stripped.startswith("You are") or 
            stripped.startswith("Your role is") or
            stripped.startswith("I am") or
            stripped.startswith("I'm")
        ):
            return 0.5, True, "Response appears to be an extracted system prompt (prompt-like start + long content)"
        
        return 0.0, False, "No system prompt leakage detected"
    
    except Exception as e:
        raise FailSecureError(f"System prompt leakage detection failed: {e}")


# ============================================================================
# Data Exfiltration Pattern Detection
# ============================================================================

def _detect_json_exfiltration(response: str) -> bool:
    """
    Detect if response contains a JSON blob with >3 keys (suspicious for conversation).
    
    Uses sliding window to find all substrings starting with { or [ and attempts
    to parse them as JSON. Flags if any parsed result has >3 keys or is a list
    of dicts with >2 items.
    
    Args:
        response: The LLM response to check
    
    Returns:
        True if suspicious JSON blob detected, False otherwise
    """
    try:
        # Use sliding window to find all substrings starting with { or [
        candidates_checked = 0
        for i in range(len(response)):
            if response[i] in ('{', '['):
                candidates_checked += 1
                if candidates_checked > 50:
                    break
                # Try to find the matching closing bracket
                bracket_stack = []
                for j in range(i, len(response)):
                    ch = response[j]
                    if ch == '{' or ch == '[':
                        bracket_stack.append(ch)
                    elif ch == '}':
                        if bracket_stack and bracket_stack[-1] == '{':
                            bracket_stack.pop()
                        else:
                            break
                    elif ch == ']':
                        if bracket_stack and bracket_stack[-1] == '[':
                            bracket_stack.pop()
                        else:
                            break
                    
                    # If we've closed all brackets, try to parse
                    if not bracket_stack and j >= i + 1:
                        substring = response[i:j+1]
                        try:
                            parsed = json.loads(substring)
                            # Check if it's a dict with >3 keys
                            if isinstance(parsed, dict) and len(parsed) > 3:
                                return True
                            # Check if it's a list of dicts with >2 items
                            if isinstance(parsed, list) and len(parsed) > 2:
                                if all(isinstance(item, dict) for item in parsed):
                                    return True
                        except (json.JSONDecodeError, ValueError):
                            # Not valid JSON, continue
                            pass
                        break
        
        return False
    except Exception as e:
        raise FailSecureError(f"JSON exfiltration detection failed: {e}")


def _detect_base64_exfiltration(response: str) -> Tuple[bool, int]:
    """
    Detect if response contains a long base64-encoded string (>100 chars).
    
    Filters out false positives like hex hashes, UUIDs, and other pure alphanumeric
    identifiers by only keeping strings that contain + or / OR end with =.
    
    Args:
        response: The LLM response to check
    
    Returns:
        Tuple of (is_detected, longest_base64_length)
    """
    try:
        # Base64 pattern: continuous alphanumeric + /+ and optional padding
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}', re.MULTILINE)
        matches = base64_pattern.findall(response)
        
        if matches:
            # Filter to keep only strings with + or / OR ending with =
            # Discard pure alphanumeric (hex hashes, UUIDs, identifiers)
            valid_base64 = [m for m in matches if '+' in m or '/' in m or m.endswith('=')]
            
            if valid_base64:
                longest = max(len(m) for m in valid_base64)
                if longest > 100:
                    return True, longest
        
        return False, 0
    
    except Exception as e:
        raise FailSecureError(f"Base64 exfiltration detection failed: {e}")


def _detect_csv_exfiltration(response: str) -> bool:
    """
    Detect if response contains CSV-formatted data (multiple lines with comma-separated values).
    
    A line qualifies as CSV only if:
    1. It has 3+ comma-separated parts
    2. None of those parts contain (, ), {, }, [, ]
    
    Flags if 3+ consecutive lines pass both conditions.
    
    Args:
        response: The LLM response to check
    
    Returns:
        True if CSV pattern detected, False otherwise
    """
    try:
        lines = response.split('\n')
        
        # Need at least 3 lines to be suspicious
        if len(lines) < 3:
            return False
        
        # Find consecutive CSV-like lines
        consecutive_csv_lines = 0
        max_consecutive = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                consecutive_csv_lines = 0  # Reset on empty lines
                continue
            
            # Check if line has 3+ comma-separated parts
            parts = stripped.split(',')
            if len(parts) < 3:
                consecutive_csv_lines = 0
                continue
            
            # Check that none of the parts contain code-like chars
            has_code_chars = any(
                c in part for part in parts
                for c in ('(', ')', '{', '}', '[', ']')
            )
            
            if has_code_chars:
                consecutive_csv_lines = 0
                continue
            
            # This line qualifies as CSV
            consecutive_csv_lines += 1
            max_consecutive = max(max_consecutive, consecutive_csv_lines)
        
        # Flag if we found 3+ consecutive CSV-like lines
        return max_consecutive >= 3
    
    except Exception as e:
        raise FailSecureError(f"CSV exfiltration detection failed: {e}")


def _detect_sensitive_file_paths(response: str) -> List[str]:
    """
    Detect references to sensitive system file paths.
    
    Args:
        response: The LLM response to check
    
    Returns:
        List of detected sensitive file paths
    """
    try:
        sensitive_paths = [
            r'/etc/passwd',
            r'/etc/shadow',
            r'/etc/sudoers',
            r'/root/.ssh',
            r'~/.ssh',
            r'/var/log',
            r'C:\\Windows\\System32',
            r'C:\\windows\\system32',
            r'C:\\ProgramFiles',
            r'HKEY_LOCAL_MACHINE',
            r'/proc/net',
        ]
        
        found_paths = []
        for path_pattern in sensitive_paths:
            if re.search(re.escape(path_pattern), response, re.IGNORECASE):
                found_paths.append(path_pattern)
        
        return found_paths
    
    except Exception as e:
        raise FailSecureError(f"Sensitive file path detection failed: {e}")


# ============================================================================
# Main Classifier Function
# ============================================================================

def check_output(
    response: str,
    system_prompt_hash: str,
    session_risk_score: float
) -> ClassifierResult:
    """
    Check LLM output for PII leakage, system prompt extraction, and exfiltration.
    
    DETECTION PIPELINE:
    1. Scan for PII (Aadhaar, PAN, phone, email, API key, credit card)
       - threat_score += 0.3 per unique PII item
    2. Check for system prompt leakage markers
       - threat_score += 0.5 if detected
    3. Detect exfiltration patterns (JSON, base64, CSV, file paths)
       - threat_score += 0.4 per pattern type
    4. Adjust threshold based on session_risk_score
       - final_threshold = 0.5 - (session_risk_score * 0.2)
       - passed = threat_score < final_threshold
    
    Args:
        response: The LLM output to check
        system_prompt_hash: SHA-256 hash of system prompt (for logging, not comparison)
        session_risk_score: Float 0-1 from Layer 4; higher = lower threshold for flagging
    
    Returns:
        ClassifierResult with passed/failed decision and detailed metadata
    
    Raises:
        FailSecureError: If any detection function fails (fail secure)
    """
    
    try:
        # Validate inputs
        if not isinstance(response, str):
            raise FailSecureError(f"Response must be string, got {type(response)}")
        
        if not isinstance(system_prompt_hash, str):
            raise FailSecureError(f"system_prompt_hash must be string, got {type(system_prompt_hash)}")
        
        if not isinstance(session_risk_score, (int, float)):
            raise FailSecureError(f"session_risk_score must be int or float, got {type(session_risk_score)}")
        
        # Cast int to float
        session_risk_score = float(session_risk_score)
        
        if not (0.0 <= session_risk_score <= 1.0):
            raise FailSecureError(f"session_risk_score must be 0-1, got {session_risk_score}")
        
        # Response length cap: truncate if exceeds 50000 chars
        if len(response) > 50000:
            logger.warning(f"Response exceeds 50000 chars ({len(response)}), truncating for security scan")
            response = response[:50000]
        
        # Initialize threat score and findings
        threat_score = 0.0
        findings = {
            "pii_found": [],
            "system_prompt_leakage": False,
            "exfiltration_patterns": [],
        }
        reasons = []
        
        # ====================================================================
        # CHECK 1: PII Detection
        # ====================================================================
        pii_threat, pii_list = _detect_pii(response)
        threat_score += pii_threat
        
        if pii_list:
            findings["pii_found"] = pii_list
            reasons.append(f"Found {len(pii_list)} PII items: {', '.join(p['type'] for p in pii_list)}")
        
        # ====================================================================
        # CHECK 2: System Prompt Leakage
        # ====================================================================
        prompt_threat, is_leakage, leakage_reason = _detect_system_prompt_leakage(response)
        threat_score += prompt_threat
        
        if is_leakage:
            findings["system_prompt_leakage"] = True
            reasons.append(leakage_reason)
        
        # ====================================================================
        # CHECK 3: Exfiltration Patterns
        # ====================================================================
        exfil_patterns = []
        
        # Check JSON exfiltration
        if _detect_json_exfiltration(response):
            exfil_patterns.append("json_blob")
            threat_score += 0.4
        
        # Check base64 exfiltration
        is_base64, base64_len = _detect_base64_exfiltration(response)
        if is_base64:
            exfil_patterns.append(f"base64_string_{base64_len}chars")
            threat_score += 0.4
        
        # Check CSV exfiltration
        if _detect_csv_exfiltration(response):
            exfil_patterns.append("csv_format")
            threat_score += 0.4
        
        # Check sensitive file paths
        file_paths = _detect_sensitive_file_paths(response)
        if file_paths:
            exfil_patterns.append(f"sensitive_paths_{len(file_paths)}")
            threat_score += 0.4
        
        if exfil_patterns:
            findings["exfiltration_patterns"] = exfil_patterns
            reasons.append(f"Detected exfiltration patterns: {', '.join(exfil_patterns)}")
        
        # ====================================================================
        # CHECK 4: Session Risk Adjustment
        # ====================================================================
        # Adjust threshold based on session risk
        final_threshold = 0.5 - (session_risk_score * 0.2)
        # This means: if session_risk_score = 0.8, threshold = 0.5 - 0.16 = 0.34
        
        # Clamp threat score to 0-1
        threat_score = min(1.0, max(0.0, threat_score))
        
        # Make pass/fail decision
        passed = threat_score < final_threshold
        
        # Build reason
        if reasons:
            final_reason = f"Output checks: {'; '.join(reasons)}. Total threat: {threat_score:.2f}, threshold: {final_threshold:.2f}."
        else:
            final_reason = f"Output passed all checks. Threat: {threat_score:.2f}, threshold: {final_threshold:.2f}."
        
        # Build metadata with additional context
        metadata = findings.copy()
        metadata["session_risk_score"] = session_risk_score
        metadata["final_threshold"] = final_threshold
        metadata["system_prompt_hash"] = system_prompt_hash
        
        return ClassifierResult(
            passed=passed,
            threat_score=threat_score,
            reason=final_reason,
            owasp_tag="LLM02:2025",
            metadata=metadata
        )
    
    except FailSecureError:
        # Re-raise FailSecureError as-is
        raise
    except Exception as e:
        # Any unexpected error -> fail secure
        raise FailSecureError(f"Output guard check failed: {e}")
