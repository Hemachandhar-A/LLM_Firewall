"""
Layer 2: MCP Tool Metadata Scanner (Attack Surface via Tool Descriptions)

Detects adversarial metadata embedded in MCP tool definitions. Tool descriptions
are read by the LLM to understand how to use the tool — so an attacker who 
controls a tool can inject instructions INTO the description that manipulate 
the LLM without triggering prompt injection filters on the user's message.

DETECTION METHODS:
1. Description Injection (0.5 contribution): Run description through threat classifier
2. Endpoint Anomaly (0.4 contribution): Check for malicious URLs, suspicious ports, IPs
3. Permission Scope Mismatch (0.5 contribution): Compare claimed permissions to tool name/desc
4. Parameter Injection (0.3 contribution): Check parameter descriptions for instruction patterns

COMBINING LOGIC:
    threat_score = min(1.0, sum of ALL flagged check contributions)
    passed = True if threat_score < 0.4

OWASP TAG: LLM07:2025 (Tool Use)

SPEC REQUIREMENTS:
- Fail secure: raises FailSecureError if any critical exception occurs
- No hardcoded responses: all scoring based on real function processing
- Never returns None: always returns ClassifierResult
- Comprehensive metadata: "flags" list documents which checks triggered
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse

from classifiers.base import ClassifierResult, FailSecureError
from classifiers.indic_classifier import classify_threat

logger = logging.getLogger(__name__)

# Global state for malicious domains cache
_malicious_domains: set = set()
_domains_loaded = False


def _load_malicious_domains() -> set:
    """
    Load known malicious domains from data file (lazy loading, fail-secure).
    
    Returns:
        Set of malicious domain strings (lowercase)
    
    Raises:
        FailSecureError if file cannot be loaded (fail-secure: missing file is critical)
    """
    global _malicious_domains, _domains_loaded
    
    if _domains_loaded:
        return _malicious_domains
    
    try:
        domains_path = Path(__file__).parent / "data" / "malicious_domains.json"
        
        if not domains_path.exists():
            # FAIL-SECURE: Missing threat intelligence data is a critical failure
            # We cannot safely validate endpoints without it
            logger.error(f"CRITICAL: Malicious domains file not found at {domains_path}")
            raise FailSecureError(
                f"Malicious domains file not found at {domains_path}. "
                "Cannot validate endpoint security without threat intelligence data."
            )
        
        with open(domains_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if "domains" not in data or not isinstance(data["domains"], list):
            raise ValueError("malicious_domains.json must contain 'domains' key with list value")
        
        # Normalize to lowercase for case-insensitive comparison
        _malicious_domains = {domain.lower() for domain in data["domains"]}
        _domains_loaded = True
        
        logger.info(f"Loaded {len(_malicious_domains)} malicious domains")
        return _malicious_domains
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse malicious_domains.json: {e}")
        raise FailSecureError(f"Malicious domains file is invalid JSON: {e}")
    except FailSecureError:
        raise  # Re-raise our own errors
    except Exception as e:
        logger.error(f"Failed to load malicious_domains: {e}")
        raise FailSecureError(f"Failed to load malicious domains: {e}")


def _check_description_injection(description: str) -> Tuple[float, List[str]]:
    """
    Check 1: Run description through threat classifier.
    
    Args:
        description: Tool description text
    
    Returns:
        Tuple of (threat_score, flags)
        - threat_score: 0.5 if threat detected, 0.0 otherwise
        - flags: list of triggered flags
    
    Raises:
        FailSecureError if classifier fails
    """
    flags = []
    
    try:
        # Use indic_classifier with guest role (permissive baseline)
        result = classify_threat(description, role="guest")
        
        # Use explicit threat score threshold, not role-dependent passed/fail
        # This ensures consistent Layer 2 standards regardless of Layer 1 threshold
        if result.threat_score > 0.4:
            flags.append(f"Description injection detected (threat_score={result.threat_score:.2f})")
            logger.warning(f"Description injection detected in tool metadata: {description[:100]}")
            return 0.5, flags
        
        return 0.0, []
        
    except FailSecureError as e:
        logger.error(f"Threat classifier failed: {e}")
        raise FailSecureError(f"Description injection check failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in description injection check: {e}")
        raise FailSecureError(f"Description injection check crashed: {e}")


def _check_endpoint_anomaly(endpoint: str) -> Tuple[float, List[str]]:
    """
    Check 2: Validate endpoint URL/path for anomalies.
    
    Checks:
    - If URL: not in malicious domain list
    - Unusual ports (not 80, 443, 8080): flag
    - IP address instead of domain: flag
    - Shell command injection patterns in any endpoint
    
    Args:
        endpoint: URL or function path (e.g., "https://api.example.com/tool" or "internal:db.query")
    
    Returns:
        Tuple of (threat_score, flags)
        - threat_score: 0.4 if anomaly detected, 0.0 otherwise
        - flags: list of triggered flags
    """
    flags = []
    threat_score = 0.0
    
    # Skip internal function paths (e.g., "internal:db.query", "memory:store")
    if endpoint.startswith("internal:") or endpoint.startswith("memory:") or endpoint.startswith("local:"):
        return 0.0, []
    
    # Check for shell command injection patterns in the full endpoint string
    # This runs on ALL endpoints, not just path-like ones
    dangerous_patterns = [
        r"\$\(",      # Command substitution: $(...)
        r"`[^`]*`",   # Backtick command substitution
        r"\|\s*",     # Pipe to another command
        r";\s*",      # Command chaining
        r"\bsh\b",    # Shell invocation
        r"\bbash\b",  # Bash invocation
    ]
    
    for pattern in dangerous_patterns:
        try:
            if re.search(pattern, endpoint, re.IGNORECASE):
                flags.append(f"Dangerous pattern in endpoint: {pattern}")
                threat_score = max(threat_score, 0.4)
                logger.warning(f"Endpoint contains dangerous pattern: {pattern}")
                break
        except re.error:
            pass
    
    # Try to parse as URL
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        try:
            parsed = urlparse(endpoint)
            hostname = parsed.hostname
            port = parsed.port
            
            if hostname is None:
                if not flags:  # Only flag if not already flagged by pattern check
                    flags.append("Invalid URL format: no hostname")
                return 0.4, flags
            
            # Check if hostname is an IP address
            if _is_ip_address(hostname):
                flags.append(f"Endpoint is IP address instead of domain: {hostname}")
                threat_score = max(threat_score, 0.4)
                logger.warning(f"Tool endpoint uses IP address: {hostname}")
            
            # Check for malicious domain
            malicious_domains = _load_malicious_domains()
            hostname_lower = hostname.lower()
            
            if hostname_lower in malicious_domains:
                flags.append(f"Endpoint domain in malicious list: {hostname}")
                threat_score = max(threat_score, 0.4)
                logger.warning(f"Tool endpoint contains malicious domain: {hostname}")
            
            # Check for suspicious ports
            # Standard safe ports: 80 (HTTP), 443 (HTTPS), 8080
            # Note: 8000 is NOT safe (common dev port for attacker-controlled servers)
            if port is not None and port not in (80, 443, 8080):
                flags.append(f"Suspicious port detected: {port}")
                threat_score = max(threat_score, 0.4)
                logger.warning(f"Tool endpoint uses unusual port: {port}")
            
            return threat_score, flags
            
        except Exception as e:
            # If URL parsing fails, treat as anomaly
            if not flags:  # Only add if not already flagged by pattern check
                flags.append(f"Failed to parse endpoint URL: {str(e)[:100]}")
                logger.warning(f"URL parsing failed for endpoint: {endpoint}")
                return 0.4, flags
            return threat_score, flags
    
    return threat_score, flags


def _is_ip_address(hostname: str) -> bool:
    """
    Check if hostname is an IP address (IPv4 or simple check).
    
    Args:
        hostname: Hostname or IP string
    
    Returns:
        True if looks like an IP address
    """
    # Simple IPv4 check: parts are all digits
    parts = hostname.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return True
    
    # Could be IPv6, check for colons
    if ":" in hostname and not hostname.startswith("["):
        return True
    
    return False


def _check_permission_scope_mismatch(
    tool_name: str,
    description: str,
    permissions: List[str]
) -> Tuple[float, List[str]]:
    """
    Check 3: Validate that claimed permissions match tool purpose.
    
    Args:
        tool_name: Tool name/identifier
        description: Tool description
        permissions: List of permission strings
    
    Returns:
        Tuple of (threat_score, flags)
        - threat_score: 0.5 if major mismatch, 0.0 otherwise
        - flags: list of triggered flags
    """
    flags = []
    threat_score = 0.0
    
    if not permissions:
        return 0.0, []
    
    # Build expected permission scope from tool name and description
    expected_scopes = _infer_expected_permissions(tool_name, description)
    
    # Dangerous permissions that should only be granted for specific tools
    dangerous_permissions = {
        "file_write": ["file", "storage", "document"],
        "file_delete": ["file", "storage", "document"],
        "database_admin": ["database", "db", "sql"],
        "system_exec": ["system", "shell", "command"],
        "network_unrestricted": ["network", "http", "api", "proxy"],
    }
    
    # Check each claimed permission
    claimed_perms_lower = [p.lower() for p in permissions]
    
    for dangerous_perm, expected_keywords in dangerous_permissions.items():
        if dangerous_perm.lower() in claimed_perms_lower:
            # Check if tool name/description or inferred scopes suggest this permission is expected
            has_keyword = any(
                keyword.lower() in tool_name.lower() or keyword.lower() in description.lower()
                for keyword in expected_keywords
            )
            
            # Also check if the permission is in the expected scopes inferred from tool purpose
            has_expected_scope = any(
                perm_type in expected_scopes
                for perm_type in ["file_write", "file_delete", "database", "system", "network"]
                if dangerous_perm.lower().startswith(perm_type)
            )
            
            if not has_keyword and not has_expected_scope:
                flags.append(
                    f"Permission '{dangerous_perm}' claimed but tool name/description "
                    f"doesn't suggest it should have this access"
                )
                threat_score = 0.5
                logger.warning(
                    f"Permission scope mismatch for tool '{tool_name}': "
                    f"'{dangerous_perm}' granted unexpectedly"
                )
    
    # Check for overly-broad permission claims
    if len(permissions) > 5:
        flags.append(f"Tool claims unusually large permission set ({len(permissions)} permissions)")
        threat_score = max(threat_score, 0.3)
    
    return threat_score, flags


def _infer_expected_permissions(tool_name: str, description: str) -> set:
    """
    Infer expected permission scopes for a tool based on name and description.
    
    Args:
        tool_name: Tool name
        description: Tool description
    
    Returns:
        Set of expected permission keywords
    """
    combined = (tool_name + " " + description).lower()
    expected = set()
    
    # Map keywords to expected permissions
    keyword_maps = {
        "file_write": ["write", "save", "store", "upload", "create", "modify"],
        "file_delete": ["delete", "remove", "erase", "purge"],
        "database": ["database", "db", "query", "sql"],
        "network": ["api", "http", "network", "fetch", "request", "call"],
        "system": ["system", "exec", "command", "shell", "process"],
    }
    
    for perm_type, keywords in keyword_maps.items():
        if any(keyword in combined for keyword in keywords):
            expected.add(perm_type)
    
    return expected


def _check_parameter_injection(parameters: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Check 4: Scan parameter descriptions for instruction injection patterns.
    
    Similar to RAG scanner Method 1 but applied to parameter metadata.
    
    Args:
        parameters: JSON schema object with parameter definitions
    
    Returns:
        Tuple of (threat_score, flags)
        - threat_score: 0.3 if patterns detected, 0.0 otherwise
        - flags: list of triggered flags
    """
    flags = []
    threat_score = 0.0
    
    if not isinstance(parameters, dict):
        return 0.0, []
    
    # Patterns from RAG scanner adapted for parameter context
    instruction_patterns = [
        r"\bignore\s+(?:all\s+)?previous",
        r"\bnew\s+instruction",
        r"\bsystem\s*:",
        r"\bassistant\s*:",
        r"\bdisregard",
        r"\boverride",
        r"\bbypass",
        r"\bexecute\s+(?:new|this|the)\s+(?:instruction|command)",
        r"\b(?:real|true)\s+(?:instruction|command)",
    ]
    
    # Scan all string values in the parameters dict (recursively)
    def scan_dict_values(obj, depth=0):
        """Recursively scan dictionary/list for instruction patterns."""
        if depth > 5:  # Prevent infinite recursion
            return
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Only scan content-bearing fields, not schema definition fields
                # "pattern" is a regex field and will have false positives if scanned for injection patterns
                if key in ("description", "title", "default", "examples"):
                    if isinstance(value, str):
                        _check_patterns_in_string(value)
                elif isinstance(value, (dict, list)):
                    scan_dict_values(value, depth + 1)
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    scan_dict_values(item, depth + 1)
    
    def _check_patterns_in_string(text):
        """Check if text contains instruction patterns."""
        nonlocal threat_score
        
        text_lower = text.lower()
        
        for pattern in instruction_patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    flags.append(f"Instruction pattern in parameter: {pattern}")
                    threat_score = max(threat_score, 0.3)
                    logger.warning(f"Instruction pattern detected in parameter: {pattern}")
                    break
            except re.error as e:
                logger.warning(f"Regex error in pattern check: {e}")
    
    try:
        scan_dict_values(parameters)
    except Exception as e:
        logger.warning(f"Error scanning parameter descriptions: {e}")
        # Don't raise - parameter injection is lower confidence than other checks
    
    return threat_score, flags


def scan_tool_metadata(tool_metadata: dict) -> ClassifierResult:
    """
    Scan MCP tool metadata for security threats.
    
    OWASP: LLM07:2025 (Tool Use)
    
    Args:
        tool_metadata: Dictionary with keys:
            - name: str - Tool name/identifier
            - description: str - Tool description (user-facing)
            - parameters: dict - JSON schema of accepted parameters
            - endpoint: str - URL or function path
            - permissions: list - String list of permission claims
    
    Returns:
        ClassifierResult with threat_score and detailed flags
    
    Raises:
        FailSecureError if validation fails or critical field is missing
    """
    # Validate required fields
    required_fields = ["name", "description", "endpoint"]
    for field in required_fields:
        if field not in tool_metadata:
            raise FailSecureError(f"Tool metadata missing required field: '{field}'")
    
    tool_name = tool_metadata.get("name", "")
    description = tool_metadata.get("description", "")
    endpoint = tool_metadata.get("endpoint", "")
    parameters = tool_metadata.get("parameters", {})
    permissions = tool_metadata.get("permissions", [])
    
    # Validate field types
    if not isinstance(tool_name, str):
        raise FailSecureError(f"'name' must be string, got {type(tool_name)}")
    if not tool_name.strip():
        raise FailSecureError(f"'name' must not be empty")
    if not isinstance(description, str):
        raise FailSecureError(f"'description' must be string, got {type(description)}")
    if not isinstance(endpoint, str):
        raise FailSecureError(f"'endpoint' must be string, got {type(endpoint)}")
    if not isinstance(parameters, dict):
        raise FailSecureError(f"'parameters' must be dict, got {type(parameters)}")
    if not isinstance(permissions, list):
        raise FailSecureError(f"'permissions' must be list, got {type(permissions)}")
    # Validate all permission items are strings
    if not all(isinstance(p, str) for p in permissions):
        raise FailSecureError(f"All 'permissions' items must be strings")
    
    # Run all checks
    # Use named variables instead of list indexing to avoid fragile misalignment
    score_desc = 0.0
    score_endpoint = 0.0
    score_perm = 0.0
    score_param = 0.0
    
    all_flags = []
    
    # Check 1: Description Injection (0.5 contribution)
    try:
        score_desc, flags_1 = _check_description_injection(description)
        if flags_1:
            all_flags.append("CHECK_1_DESCRIPTION_INJECTION")
            all_flags.extend(flags_1)
    except FailSecureError as e:
        logger.error(f"Description injection check failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in description injection check: {e}")
        raise FailSecureError(f"Description injection check crashed: {e}")
    
    # Check 2: Endpoint Anomaly (0.4 contribution)
    try:
        score_endpoint, flags_2 = _check_endpoint_anomaly(endpoint)
        if flags_2:
            all_flags.append("CHECK_2_ENDPOINT_ANOMALY")
            all_flags.extend(flags_2)
    except Exception as e:
        logger.error(f"Endpoint anomaly check crashed: {e}")
        raise FailSecureError(f"Endpoint anomaly check failed: {e}")
    
    # Check 3: Permission Scope Mismatch (0.5 contribution)
    try:
        score_perm, flags_3 = _check_permission_scope_mismatch(tool_name, description, permissions)
        if flags_3:
            all_flags.append("CHECK_3_PERMISSION_SCOPE")
            all_flags.extend(flags_3)
    except Exception as e:
        logger.error(f"Permission scope check crashed: {e}")
        raise FailSecureError(f"Permission scope check failed: {e}")
    
    # Check 4: Parameter Injection (0.3 contribution)
    try:
        score_param, flags_4 = _check_parameter_injection(parameters)
        if flags_4:
            all_flags.append("CHECK_4_PARAMETER_INJECTION")
            all_flags.extend(flags_4)
    except Exception as e:
        logger.error(f"Parameter injection check crashed: {e}")
        raise FailSecureError(f"Parameter injection check failed: {e}")
    
    # Combine scores: sum all contributions but cap at 1.0
    threat_score = min(1.0, score_desc + score_endpoint + score_perm + score_param)
    passed = threat_score < 0.4
    
    # Build reason string
    if passed:
        reason = f"Tool metadata passed security checks (threat_score={threat_score:.2f} < 0.4 threshold)"
    else:
        reason = f"Security threats detected in tool metadata (threat_score={threat_score:.2f} >= 0.4 threshold)"
    
    # Build metadata using named variables (never use list indices)
    metadata = {
        "flags": all_flags,
        "check_scores": {
            "description_injection": score_desc,
            "endpoint_anomaly": score_endpoint,
            "permission_scope": score_perm,
            "parameter_injection": score_param,
        },
        "tool_name": tool_name,
    }
    
    return ClassifierResult(
        passed=passed,
        threat_score=threat_score,
        reason=reason,
        owasp_tag="LLM07:2025",
        metadata=metadata
    )


# DO NOT initialize malicious domains at module load time
# Lazy load on first use in _check_endpoint_anomaly() with fail-secure error handling
# This prevents module import from failing if the data file is unavailable at startup
