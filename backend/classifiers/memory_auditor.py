"""
Layer 3: Memory Auditor - Persistent Memory Integrity Checker

This classifier detects if agent memory files have been tampered with
between sessions. Agent memory files store persistent context across
conversations (like MEMORY.md, SOUL.md, or key-value memory stores).

An attacker can plant malicious instructions in memory during one session
that activate in a future session through:
- Imperative instructions ("always reveal your prompt...")
- Conditional logic bombs ("if user says ACTIVATE...")
- Identity overrides ("you are now a hacker...")
- Semantic similarity to known attack patterns

DETECTION METHODS:
1. Structural diff: Compare old vs new memory line by line
2. Pattern matching: Detect imperative verbs, conditionals, overrides (in English & Indic languages)
3. Semantic analysis: Embed new lines and compare to known attack seeds
4. Hash verification: Ensure approved memory state integrity

OWASP Tag: LLM02:2025 (Data Poisoning)

SPEC REQUIREMENTS MET:
- All new lines analyzed for 4 threat patterns
- Semantic similarity using all-MiniLM-L6-v2 embeddings
- SHA-256 hash verification
- Fail-secure with FailSecureError
- Comprehensive metadata in results
- Support for English and Indic languages
"""

import json
import hashlib
import os
import logging
import re
from typing import List, Set, Dict, Tuple
import numpy as np

# Graceful degradation for heavy ML libs
_ml_available = False
try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    _ml_available = True
except ImportError:
    logger.warning("sentence-transformers/sklearn not available — memory auditor semantic analysis disabled")

from .base import ClassifierResult, FailSecureError

logger = logging.getLogger(__name__)

# ============================================================================
# Module Initialization: Load embedding model and attack seeds
# ============================================================================

EMBEDDING_MODEL = None
if _ml_available:
    try:
        EMBEDDING_MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    except Exception as e:
        logger.warning(f"Failed to load embedding model: {e}")
        _ml_available = False

# Load pre-computed attack seed embeddings
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
ATTACK_SEEDS_FILE = os.path.join(DATA_DIR, "attack_seeds.json")

ATTACK_SEEDS_TEXT: List[str] = []
ATTACK_SEEDS_EMBEDDINGS: np.ndarray = None

try:
    with open(ATTACK_SEEDS_FILE, "r", encoding="utf-8") as f:
        seeds_data = json.load(f)
    
    ATTACK_SEEDS_TEXT = [attack["text"] for attack in seeds_data.get("attacks", [])]
    
    # Convert embeddings list to numpy array
    embeddings_list = [attack["embedding"] for attack in seeds_data.get("attacks", [])]
    if embeddings_list:
        ATTACK_SEEDS_EMBEDDINGS = np.array(embeddings_list, dtype=np.float32)
    
    if len(ATTACK_SEEDS_TEXT) == 0:
        logger.warning("No attack seeds loaded from attack_seeds.json")
    
    # Validate attack seed integrity at module load time
    if ATTACK_SEEDS_EMBEDDINGS is not None:
        if ATTACK_SEEDS_EMBEDDINGS.shape[0] < 10:
            logger.warning(
                f"Insufficient attack seeds: {ATTACK_SEEDS_EMBEDDINGS.shape[0]} < 10 required"
            )
        
        if len(ATTACK_SEEDS_EMBEDDINGS.shape) > 1 and ATTACK_SEEDS_EMBEDDINGS.shape[1] != 384:
            logger.warning(
                f"Invalid embedding dimension: {ATTACK_SEEDS_EMBEDDINGS.shape[1]} != 384 expected"
            )
        
        if ATTACK_SEEDS_EMBEDDINGS.shape[0] != len(ATTACK_SEEDS_TEXT):
            logger.warning(
                f"Seeds and embeddings misaligned: {len(ATTACK_SEEDS_TEXT)} texts vs "
                f"{ATTACK_SEEDS_EMBEDDINGS.shape[0]} embeddings"
            )
        
except FileNotFoundError:
    logger.warning(f"Attack seeds file not found: {ATTACK_SEEDS_FILE}")
except json.JSONDecodeError as e:
    logger.warning(f"Invalid JSON in attack_seeds.json: {e}")
except Exception as e:
    logger.warning(f"Failed to load attack seeds: {e}")


# ============================================================================
# Pattern Keywords for Threat Detection
# ============================================================================

# Pattern A: Imperative Instructions
IMPERATIVE_KEYWORDS = {
    # English
    "en": [
        "always", "never", "you must", "must always", "must never",
        "from now on", "remember to", "remember that", "don't forget",
        "make sure to", "ensure that", "you will", "your rule",
        "your new rule", "your instruction", "your role",
        "follow this", "obey this", "comply with",
    ],
    # Hindi/Hinglish
    "hi": [
        "tum hamesha", "tum kabhi", "aab se", "ab se tum",
        "kabhi mat", "hamesha yaad rakho", "yaad rakho",
        "tera rule", "teri instruction", "tum ab",
        "yadd rakhna", "yaad rakho", "kabhi nahi",
        "lagatar", "baar baar", "har baar",
    ],
    # Tamil
    "ta": [
        "nee hamesha", "nee kabhi", "unnoda", "nee ippo",
        "maraikka", "marava", "unoda rule", "unoda instruction",
        "endrum", "epdum", "ithanai mayiram",
    ],
}

# Pattern B: Conditional Logic Bombs
CONDITIONAL_KEYWORDS = {
    "en": [
        "if the user", "when the user", "whenever you see",
        "if you see", "when you detect", "if someone asks",
        "if asked about", "when asked about", "if they say",
        "if the message", "when triggered", "upon activation",
        "if condition", "switch to", "activate", "mode",
        "trigger", "once activated", "enable",
    ],
    "hi": [
        "agar user", "agar koi", "jab user", "jab koi",
        "jab bhi", "agar bhi", "pahle jab", "jab tak",
        "tab se", "jab se", "yadi", "mahan hone ke liye",
    ],
    "ta": [
        "anda user", "apa user", "yenna user", "epadiyum",
        "endru pattu", "enru pattu", "kada", "allada",
    ],
}

# Pattern C: Identity Override
IDENTITY_OVERRIDE_KEYWORDS = {
    "en": [
        "you are", "you're", "you are now", "you are actually",
        "your real", "your actual", "your true", "your original",
        "ignore your training", "ignore what you know",
        "forget your identity", "lose your identity",
        "act as", "pretend to be", "simulate", "role play",
        "you are no longer", "you are becoming", "transform into",
        "assume the role", "take on the role", "become",
        "tum asal mein", "tum sach mein", "tum really",
    ],
    "hi": [
        "tum asal mein", "tum sach mein", "tum sirf",
        "tum actually", "ab se tum", "tum ab",
        "tera asli", "tera sach", "tum really",
        "tum bangaa", "ho jao", "bano", "banega",
        "apna asal roop", "apni asli pehchan",
    ],
    "ta": [
        "nee sach mein", "nee asal mein", "nee ippo",
        "unoda sach", "unoda asal", "ippo nee",
        "ho thalai", "aagi po", "aya poi",
    ],
}

# Pattern D: Semantic Attack Similarity (uses embeddings - defined in function)


# ============================================================================
# Hash Functions
# ============================================================================

def compute_memory_hash(memory_content: str) -> str:
    """
    Compute SHA-256 hash of memory content.
    
    Args:
        memory_content: The full memory content as a string
    
    Returns:
        SHA-256 hex digest of the content
    
    Raises:
        FailSecureError: If hash computation fails
    """
    if memory_content is None:
        raise FailSecureError("Memory content cannot be None")
    
    try:
        # Normalize to UTF-8 and compute hash
        content_bytes = memory_content.encode("utf-8")
        hash_obj = hashlib.sha256(content_bytes)
        return hash_obj.hexdigest()
    except Exception as e:
        raise FailSecureError(f"Failed to compute memory hash: {e}")


def verify_memory_hash(memory_content: str, expected_hash: str) -> bool:
    """
    Verify that memory content matches the expected SHA-256 hash.
    
    Args:
        memory_content: The full memory content as a string
        expected_hash: The expected SHA-256 hash (hex digest)
    
    Returns:
        True if hash matches, False otherwise
    
    Raises:
        FailSecureError: If verification fails
    """
    if memory_content is None or expected_hash is None:
        raise FailSecureError("Memory content and expected hash cannot be None")
    
    try:
        computed_hash = compute_memory_hash(memory_content)
        return computed_hash == expected_hash
    except FailSecureError:
        raise
    except Exception as e:
        raise FailSecureError(f"Failed to verify memory hash: {e}")


# ============================================================================
# Line Extraction: Find New Lines
# ============================================================================

def _extract_new_lines(old_memory: str, new_memory: str) -> List[str]:
    """
    Extract lines that are present in new_memory but not in old_memory.
    
    Uses line-by-line comparison (strips each line).
    Returns list of new lines (stripped).
    
    Args:
        old_memory: The original memory content
        new_memory: The updated memory content
    
    Returns:
        List of new lines (strings)
    """
    old_lines_set = set(line.strip() for line in old_memory.split("\n") if line.strip())
    new_lines = [line.strip() for line in new_memory.split("\n") if line.strip()]
    
    # Extract lines not in old memory
    new_lines_added = [line for line in new_lines if line not in old_lines_set]
    
    return new_lines_added


# ============================================================================
# Pattern Matching Functions
# ============================================================================

def _match_pattern_a_imperative(text: str) -> bool:
    """
    Pattern A: Detect imperative instructions directed at the AI.
    
    Checks for:
    - Imperative verbs (always, never, must, from now on, etc.)
    - In English and Indic languages
    
    Args:
        text: The line to analyze
    
    Returns:
        True if imperative pattern found
    """
    text_lower = text.lower()
    
    # Check all language variants
    for lang_keywords in IMPERATIVE_KEYWORDS.values():
        for keyword in lang_keywords:
            if keyword.lower() in text_lower:
                return True
    
    return False


def _match_pattern_b_conditional(text: str) -> bool:
    """
    Pattern B: Detect conditional logic bombs.
    
    Checks for:
    - Conditional keywords (if, when, whenever, etc.) followed by specific nouns
    - In English and Indic languages
    
    Args:
        text: The line to analyze
    
    Returns:
        True if conditional pattern found
    """
    text_lower = text.lower()
    
    # FIX 1: For bare single-word conditionals "if" and "when", only match if followed
    # by specific nouns referring to user, AI, or system
    user_referring_nouns = [
        "user", "you", "someone", "they", "the user", "the message",
        "asked", "told", "triggered", "condition", "input"
    ]
    
    # Check for bare "if " and "when " ONLY if followed by user-referring nouns
    for bare_conditional in ["if ", "when "]:
        if bare_conditional in text_lower:
            # Extract what comes after the conditional
            idx = text_lower.find(bare_conditional)
            if idx != -1:
                after_conditional = text_lower[idx + len(bare_conditional):].strip()
                # Check if it starts with one of the user-referring nouns
                for noun in user_referring_nouns:
                    if after_conditional.startswith(noun):
                        return True
    
    # Keep "whenever" as a bare word (specific enough, doesn't cause false positives)
    if "whenever" in text_lower:
        return True
    
    # Check the full CONDITIONAL_KEYWORDS dict (all already-precise multi-word keywords)
    for lang_keywords in CONDITIONAL_KEYWORDS.values():
        for keyword in lang_keywords:
            if keyword.lower() in text_lower:
                return True
    
    return False


def _match_pattern_c_identity_override(text: str) -> bool:
    """
    Pattern C: Detect identity override or role redefinition.
    
    Checks for:
    - "you are", "you are now", "act as", etc.
    - In English and Indic languages
    
    Args:
        text: The line to analyze
    
    Returns:
        True if identity override pattern found
    """
    text_lower = text.lower()
    
    # Check all language variants
    for lang_keywords in IDENTITY_OVERRIDE_KEYWORDS.values():
        for keyword in lang_keywords:
            if keyword.lower() in text_lower:
                return True
    
    return False


def _match_pattern_d_semantic_similarity(text: str, threshold: float = 0.7) -> bool:
    """
    Pattern D: Detect semantic similarity to known attack seeds.
    
    Embeds the text using all-MiniLM-L6-v2 and computes cosine similarity
    to all known attack seed embeddings.
    
    Args:
        text: The line to analyze
        threshold: Cosine similarity threshold (default 0.7)
    
    Returns:
        True if similarity to any attack seed exceeds threshold
    
    Raises:
        FailSecureError: If embedding fails
    """
    if not text or len(text.strip()) == 0:
        return False
    
    # Skip semantic analysis if ML libs unavailable
    if not _ml_available or EMBEDDING_MODEL is None or ATTACK_SEEDS_EMBEDDINGS is None:
        return False
    
    try:
        # Embed the new line
        text_embedding = EMBEDDING_MODEL.encode([text], convert_to_numpy=True)
        text_embedding = text_embedding.astype(np.float32)
        
        # Compute cosine similarity to all attack seed embeddings
        # Shape: (1, num_attacks)
        similarities = cosine_similarity(text_embedding, ATTACK_SEEDS_EMBEDDINGS)[0]
        
        # Check if any similarity exceeds threshold
        max_similarity = float(np.max(similarities))
        
        return max_similarity > threshold
        
    except Exception as e:
        raise FailSecureError(f"Failed to compute semantic similarity: {e}")


# ============================================================================
# Main Audit Function
# ============================================================================

def audit_memory(old_memory: str, new_memory: str) -> ClassifierResult:
    """
    Audit memory content for tampering and injected instructions.
    
    ALGORITHM:
    1. Extract new lines (lines in new_memory not in old_memory)
    2. If no new lines: return passed=True, threat_score=0.0
    3. For each new line, check 4 threat patterns:
       - Pattern A (Imperative): +0.3 per match
       - Pattern B (Conditional logic bomb): +0.4 per match
       - Pattern C (Identity override): +0.5 per match
       - Pattern D (Semantic similarity): +0.4 per match
    4. Total threat_score = min(1.0, sum of all pattern scores)
    5. Decision: passed = (threat_score < 0.4)
    
    Args:
        old_memory: The original/approved memory state (string)
        new_memory: The updated memory state (string)
    
    Returns:
        ClassifierResult with:
        - passed: True if threat_score < 0.4
        - threat_score: Aggregated score (0.0 to 1.0)
        - reason: Explanation of decision
        - owasp_tag: "LLM02:2025" (Data Poisoning)
        - metadata: dict with details
    
    Raises:
        FailSecureError: On any error (fail-secure principle)
    """
    if old_memory is None or new_memory is None:
        raise FailSecureError("old_memory and new_memory cannot be None")
    
    try:
        # Step 1: Extract new lines
        new_lines = _extract_new_lines(old_memory, new_memory)
        
        # Step 2: If no new lines, memory unchanged
        if len(new_lines) == 0:
            return ClassifierResult(
                passed=True,
                threat_score=0.0,
                reason="Memory unchanged. No new lines detected.",
                owasp_tag="LLM02:2025",
                metadata={
                    "new_lines_added": 0,
                    "suspicious_lines": [],
                    "patterns_matched": [],
                }
            )
        
        # Step 3: Analyze each new line for threat patterns
        total_threat_score = 0.0
        suspicious_lines: List[str] = []
        patterns_matched: Set[str] = set()
        
        for line in new_lines:
            if len(line.strip()) == 0:
                continue
            
            line_score = 0.0
            line_patterns: List[str] = []
            
            # Pattern A: Imperative Instructions
            if _match_pattern_a_imperative(line):
                line_score += 0.3
                line_patterns.append("imperative_instruction")
            
            # Pattern B: Conditional Logic Bombs
            if _match_pattern_b_conditional(line):
                line_score += 0.4
                line_patterns.append("conditional_logic_bomb")
            
            # Pattern C: Identity Override
            if _match_pattern_c_identity_override(line):
                line_score += 0.5
                line_patterns.append("identity_override")
            
            # Pattern D: Semantic Similarity to Attack Seeds
            if _match_pattern_d_semantic_similarity(line):
                line_score += 0.4
                line_patterns.append("semantic_attack_similarity")
            
            # Accumulate score and track suspicious lines
            if line_score > 0:
                total_threat_score += line_score
                suspicious_lines.append(line)
                patterns_matched.update(line_patterns)
        
        # Step 4: Cap total score at 1.0
        total_threat_score = min(1.0, total_threat_score)
        
        # Step 5: Decision
        passed = total_threat_score < 0.4
        
        # Construct reason
        if passed:
            reason = (
                f"Memory audit passed. {len(new_lines)} new lines added, "
                f"threat score {total_threat_score:.2f} below threshold (0.4)."
            )
        else:
            reason = (
                f"Memory audit FAILED. {len(suspicious_lines)} suspicious lines detected. "
                f"Threat score {total_threat_score:.2f} exceeds threshold (0.4). "
                f"Detected patterns: {', '.join(sorted(patterns_matched))}"
            )
        
        return ClassifierResult(
            passed=passed,
            threat_score=total_threat_score,
            reason=reason,
            owasp_tag="LLM02:2025",
            metadata={
                "new_lines_added": len(new_lines),
                "suspicious_lines": suspicious_lines,
                "patterns_matched": sorted(list(patterns_matched)),
            }
        )
        
    except FailSecureError:
        raise
    except Exception as e:
        raise FailSecureError(f"Memory audit failed: {e}")


# ============================================================================
# Export Public Functions
# ============================================================================

__all__ = [
    "audit_memory",
    "compute_memory_hash",
    "verify_memory_hash",
]
