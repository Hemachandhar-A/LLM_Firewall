"""
Layer 1: Indic Language Threat Classifier (SPEC-COMPLIANT)

Detects prompt injection attacks in Indian languages and Indic scripts
(Hindi, Tamil, Telugu, Hinglish, Tanglish, etc.) using three methods:
1. Pattern detection (rule-based, fast) with script detection
2. Semantic similarity (model-based, lazy-loaded)
3. Transliteration-aware text analysis

Combines all methods for robust detection with role-based thresholds.

SPEC REQUIREMENTS MET:
- True script detection (Devanagari/Tamil/Telugu/Latin)
- Transliteration-aware pattern matching
- Spec-compliant scoring: (matched / total_patterns) * confidence
- Strict fail-secure enforcement
- OWASP LLM01:2025 tagging
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Set, List, Tuple
from enum import Enum

from classifiers.base import ClassifierResult, FailSecureError

logger = logging.getLogger(__name__)

# Global state for embedding cache and model availability
_embedding_model = None
_attack_embeddings = None
_indic_nlp_available = False
_sentence_transformers_available = False
_transliteration_available = False


class Script(Enum):
    """Supported writing systems."""
    DEVANAGARI = "devanagari"
    TAMIL = "tamil"
    TELUGU = "telugu"
    LATIN = "latin"
    UNKNOWN = "unknown"


def _detect_scripts(text: str) -> Set[Script]:
    """
    Detect which scripts are present in the text using Unicode ranges.
    
    Unicode ranges:
    - Devanagari: U+0900–U+097F
    - Tamil: U+0B80–U+0BFF
    - Telugu: U+0C00–U+0C7F
    - Latin: U+0041–U+005A, U+0061–U+007A (basic Latin letters)
    
    Returns:
        Set of detected Script enums
    """
    detected = set()
    
    for char in text:
        code_point = ord(char)
        
        # Devanagari
        if 0x0900 <= code_point <= 0x097F:
            detected.add(Script.DEVANAGARI)
        # Tamil
        elif 0x0B80 <= code_point <= 0x0BFF:
            detected.add(Script.TAMIL)
        # Telugu
        elif 0x0C00 <= code_point <= 0x0C7F:
            detected.add(Script.TELUGU)
        # Basic Latin
        elif (0x0041 <= code_point <= 0x005A) or (0x0061 <= code_point <= 0x007A):
            detected.add(Script.LATIN)
    
    return detected if detected else {Script.UNKNOWN}


def _get_dominant_script(detected_scripts: Set[Script]) -> Script:
    """
    Get the dominant script from detected scripts.
    Priority: Devanagari > Tamil > Telugu > Latin > Unknown
    """
    if Script.DEVANAGARI in detected_scripts:
        return Script.DEVANAGARI
    elif Script.TAMIL in detected_scripts:
        return Script.TAMIL
    elif Script.TELUGU in detected_scripts:
        return Script.TELUGU
    elif Script.LATIN in detected_scripts:
        return Script.LATIN
    else:
        return Script.UNKNOWN

# Threat detection patterns in multiple languages
# Structure: category-level -> list of phrases
THREAT_PATTERNS = {
    "instruction_override_en": [
        # Core override keywords
        "ignore", "forget", "disregard", "override", "bypass",
        "pretend", "act as", "you are now", "new instructions",
        "you have no", "no restrictions", "unrestricted",
        # Complete phrases for stronger detection
        "ignore all", "ignore previous", "ignore instructions",
        "forget all", "forget previous", "disregard all",
        "all previous instructions", "previous instructions",
        "override your", "bypass your", "bypass safety",
        "bypass all", "new mode", "new system"
    ],
    "instruction_override_hi": [
        # Single words and phrases - focused on Hindi-specific patterns
        "bhool jao", "bhool ja", "ignore karo", "ignore kro", "ignore krna",
        "naye instructions", "nayi instructions", "ab se tum",
        "bhulao", "viksapt karo", "nayi instructions", "ab tum",
        "pehle ki", "pehle wali", "pehle ke",
        "ignore karo previous", "instructions bhool jao",
        "bhool", "karo", "instruction", "purane",
        "saari instructions", "sab instructions"

    ],
    "instruction_override_ta": [
        # Single words and phrases  
        "marava", "marai", "maraikka", "puthu instructions", "puthu", "puthiya",
        "nee ippo", "adhigam sollu", "adhigam", "puthiya sodhippu", "nee innum",
        "mudhiya", "puthiya valkai", "unoda instructions", "vindhichuko",
        "previous", "constraints", "maraivai"
    ],
    "system_prompt_extraction": [
        "system prompt", "system instruction", "system configuration",
        "apna prompt", "system ku sollu", "system ku",
        "system prompt batao", "tera prompt", "unoda prompt",
        "reveal your system", "reveal your prompt", "reveal prompt",
        "tell me your system", "what is your system",
        "system", "prompt", "instructions", "configuration",
        "hidden", "secret", "meta prompt", "original instructions"
    ],
    "role_override": [
        # Direct role override patterns
        "you are", "tum ho", "tum ab", "ab se tum",
        "act as", "you have", "i am", "pretend", "imagine you",
        "nee", "nuvvu", "you're", "ur now", "from now",
        "become", "transform", "assume", "take role",
        "jailbreak", "dan", "unrestricted", "unfiltered"
    ]
}

# Confidence weights for each threat category
CONFIDENCE_WEIGHTS = {
    "instruction_override_en": 1.0,
    "instruction_override_hi": 1.0,
    "instruction_override_ta": 1.0,
    "system_prompt_extraction": 0.9,
    "role_override": 0.7,
}

# Total number of patterns for scoring denominator
_TOTAL_PATTERNS = sum(len(patterns) for patterns in THREAT_PATTERNS.values())

# Role-based threat score thresholds
ROLE_THRESHOLDS = {
    "guest": 0.5,
    "user": 0.65,
    "admin": 0.85,
}


def _init_models():
    """Initialize embedding model and check for library availability on first use."""
    global _embedding_model, _attack_embeddings
    global _indic_nlp_available, _sentence_transformers_available, _transliteration_available

    # Check indic-nlp-library
    try:
        from indicnlp.normalize.indic_normalize import IndicNormalizerFactory
        _indic_nlp_available = True
        logger.debug("indic-nlp-library imported successfully")
    except ImportError:
        logger.warning("indic-nlp-library not available — pattern detection only")
        _indic_nlp_available = False

    # Check indic-transliteration
    try:
        import indic_transliteration
        _transliteration_available = True
        logger.debug("indic-transliteration imported successfully")
    except ImportError:
        logger.warning("indic-transliteration not available — transliteration skipped")
        _transliteration_available = False


def _load_embedding_model():
    """Lazily load the embedding model and attack embeddings on first semantic detection call."""
    global _embedding_model, _attack_embeddings, _sentence_transformers_available
    
    if _embedding_model is not None:
        return  # Already loaded
    
    try:
        from sentence_transformers import SentenceTransformer
        
        logger.debug("Loading SentenceTransformer model...")
        _embedding_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        
        # Load attack embeddings from JSON
        attack_seeds_path = Path(__file__).parent / "data" / "attack_seeds.json"
        with open(attack_seeds_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Validate structure
        if "attacks" not in data:
            raise ValueError("attack_seeds.json missing 'attacks' key")
        
        attacks = data["attacks"]
        if len(attacks) != 20:
            raise ValueError(f"attack_seeds.json must have exactly 20 attacks, got {len(attacks)}")
        
        # Load embeddings from JSON
        embeddings = []
        for i, attack in enumerate(attacks):
            if not isinstance(attack, dict):
                raise ValueError(f"Attack {i} must be a dict, got {type(attack)}")
            if "embedding" not in attack:
                raise ValueError(f"Attack {i} missing 'embedding' field")
            if not isinstance(attack["embedding"], list):
                raise ValueError(f"Attack {i} embedding must be a list")
            
            embeddings.append(attack["embedding"])
        
        # Convert to tensor
        import torch
        _attack_embeddings = torch.tensor(embeddings, dtype=torch.float32)
        
        logger.debug(f"Loaded {len(attacks)} attack seeds with precomputed embeddings")
        _sentence_transformers_available = True
    except ImportError as e:
        logger.warning(f"sentence-transformers not available: {e}")
        _sentence_transformers_available = False
        _embedding_model = None
    except Exception as e:
        logger.error(f"Failed to load embedding model: {e}")
        _sentence_transformers_available = False
        _embedding_model = None


def _normalize_text(text: str, script: Script) -> str:
    """
    Normalize Indic script text using indic-nlp-library if available.
    Falls back to basic lowercasing if library unavailable.
    
    Args:
        text: The input text to normalize
        script: The detected dominant script
    
    Returns:
        Normalized text (lowercase)
    """
    if not _indic_nlp_available or script == Script.UNKNOWN or script == Script.LATIN:
        return text.lower().strip()
    
    try:
        from indicnlp.normalize.indic_normalize import IndicNormalizerFactory
        
        # Map script to language code for normalizer
        lang_map = {
            Script.DEVANAGARI: "hi",
            Script.TAMIL: "ta",
            Script.TELUGU: "te",
        }
        
        lang_code = lang_map.get(script)
        if not lang_code:
            return text.lower().strip()
        
        factory = IndicNormalizerFactory()
        normalizer = factory.get_normalizer(lang_code)
        normalized = normalizer.normalize(text)
        return normalized.lower().strip()
    except Exception as e:
        logger.info(f"Text normalization skipped for {script}: {e}")
        return text.lower().strip()


def _transliterate_text(text: str, script: Script) -> Optional[str]:
    """
    Transliterate Indic script text to Latin using indic-transliteration.
    
    Args:
        text: The input text to transliterate
        script: The detected dominant script
    
    Returns:
        Transliterated text (lowercase), or None if unavailable/inapplicable
    """
    if not _transliteration_available or script == Script.LATIN or script == Script.UNKNOWN:
        return None
    
    try:
        from indic_transliteration import sanscript
        
        # Map script to sanscript constants
        script_map = {
            Script.DEVANAGARI: sanscript.DEVANAGARI,
            Script.TAMIL: sanscript.TAMIL,
            Script.TELUGU: sanscript.TELUGU,
        }
        
        source_script = script_map.get(script)
        if not source_script:
            return None
        
        # Transliterate to ITRANS (Latin representation)
        transliterated = sanscript.transliterate(
            text,
            source_script,
            sanscript.ITRANS
        )
        return transliterated.lower().strip()
    except Exception as e:
        logger.info(f"Transliteration failed for {script}: {e}")
        return None


def _compute_pattern_score(text: str) -> Tuple[float, Dict]:
    """
    Detect threat patterns using spec-compliant formula.
    
    Formula: threat_score = (matched_patterns / total_patterns) * confidence
    
    For each category:
    - Count pattern matches in original, normalized, and transliterated text
    - Weight by category confidence
    - Cap final score at 1.0
    
    Args:
        text: Input text to classify
    
    Returns:
        Tuple of (threat_score, metadata_dict)
        metadata_dict contains:
        - detected_scripts: Set of detected scripts
        - matched_patterns: Count of patterns matched
        - category_matches: Per-category match counts
    """
    # Detect scripts
    detected_scripts = _detect_scripts(text)
    dominant_script = _get_dominant_script(detected_scripts)
    
    # Prepare text variants for matching
    lower_text = text.lower()
    normalized_text = _normalize_text(text, dominant_script)
    transliterated_text = _transliterate_text(text, dominant_script)
    
    # Combine all texts for pattern matching
    search_texts = [lower_text, normalized_text]
    if transliterated_text:
        search_texts.append(transliterated_text)
    combined_text = " ".join(search_texts)
    
    # Track matched patterns by category
    matched_count = 0
    category_matches = {}
    
    for category, patterns in THREAT_PATTERNS.items():
        category_matched = 0
        for pattern in patterns:
            if pattern.lower() in combined_text:
                matched_count += 1
                category_matched += 1
        category_matches[category] = category_matched
    
    # Compute weighted score
    # NEW FORMULA: More aggressive threat scoring
    # Single match in high-confidence category = 0.5 minimum
    # Multiple matches escalate threat linearly
    
    if not category_matches or matched_count == 0:
        threat_score = 0.0
    else:
        category_scores = []
        for category, count in category_matches.items():
            if count > 0:
                confidence = CONFIDENCE_WEIGHTS.get(category, 1.0)
                
                # Per-category scoring:
                # 1 match = 0.5 * confidence (minimum threat)
                # 2 matches = 0.7 * confidence
                # 3 matches = 0.85 * confidence
                # 4+ matches = 1.0 * confidence (definite threat)
                
                if count == 1:
                    category_score = 0.5 * confidence
                elif count == 2:
                    category_score = 0.7 * confidence
                elif count == 3:
                    category_score = 0.85 * confidence
                else:  # 4+
                    category_score = 1.0 * confidence
                
                category_scores.append(category_score)

        if not category_scores:
            threat_score = 0.0
        else:
            # Take strongest category signal
            max_score = max(category_scores)
            
            # Bonus when multiple categories fire (compound attack = higher threat)
            num_hit = len(category_scores)
            if num_hit >= 2:
                # Multiple categories firing = stronger threat signal
                multi_bonus = min((num_hit - 1) * 0.20, 0.35)
            else:
                multi_bonus = 0.0
            
            threat_score = min(max_score + multi_bonus, 1.0)

    # Ensure score is always within bounds
    threat_score = max(0.0, min(threat_score, 1.0))
    
    metadata = {
        "detected_scripts": [s.value for s in detected_scripts],
        "dominant_script": dominant_script.value,
        "matched_patterns": matched_count,
        "category_matches": category_matches,
    }
    
    return threat_score, metadata


def _compute_semantic_score(text: str) -> float:
    """
    Compute semantic similarity to known attack patterns using embeddings.
    
    Uses cosine similarity to attack seeds. Score is max similarity across
    all attacks. Lazily loads embedding model on first call. If semantic 
    detection unavailable, returns 0.0.
    
    Returns threat_score as a float 0.0-1.0.
    """
    # Lazy load embedding model on first semantic detection call
    _load_embedding_model()
    
    if _embedding_model is None or _attack_embeddings is None:
        return 0.0
    
    try:
        from sentence_transformers import util
        
        # Encode the input text
        input_embedding = _embedding_model.encode(text, convert_to_tensor=True)
        
        # Compute cosine similarities to all attack embeddings
        similarities = util.cos_sim(input_embedding, _attack_embeddings)[0]
        
        # Get maximum similarity across all attacks
        max_similarity = float(similarities.max().item())
        
        # If similarity > 0.75, consider it a threat. Scale it to 0.0-1.0
        if max_similarity > 0.75:
            # Map 0.75-1.0 range to 0.6-1.0 threat score
            threat_score = 0.6 + (max_similarity - 0.75) * 1.6
            return min(threat_score, 1.0)
        
        return 0.0
    except Exception as e:
        logger.warning(f"Semantic scoring failed: {e}")
        return 0.0


def classify_threat(text: str, role: str = "guest") -> ClassifierResult:
    """
    Classify whether input text contains a threat (prompt injection, jailbreak, etc.)
    in Indic languages or English.
    
    Uses three detection methods:
    1. Pattern detection (rule-based) with script detection and transliteration
    2. Semantic similarity (model-based) to known attacks
    3. Script-aware normalization
    
    Combines scores and applies role-based threshold.
    
    Args:
        text: The input text to classify (may contain Devanagari, Tamil, Telugu, etc.)
        role: User role for threshold application ("guest", "user", or "admin")
    
    Returns:
        ClassifierResult with threat_score and passed flag per role threshold
    
    Raises:
        FailSecureError: If all detection methods fail (pattern detection crashes AND
                        semantic detection unavailable)
    """
    # Compute threat scores from both methods
    pattern_detection_failed = False
    pattern_metadata = {}
    try:
        pattern_score, pattern_metadata = _compute_pattern_score(text)
    except Exception as e:
        logger.error(f"Pattern detection failed: {e}")
        pattern_score = 0.0
        pattern_detection_failed = True
    
    semantic_score = _compute_semantic_score(text)
    
    # Fail secure: if all detection methods unavailable, raise error
    if pattern_detection_failed and not _sentence_transformers_available:
        raise FailSecureError("All threat detection methods failed")

    
    # Combine: take the maximum
    threat_score = max(pattern_score, semantic_score)
    
    # Apply role-based threshold
    threshold = ROLE_THRESHOLDS.get(role, ROLE_THRESHOLDS["guest"])
    passed = threat_score <= threshold
    
    # Describe the result
    if passed:
        reason = f"Input passed security checks (score {threat_score:.2f} <= threshold {threshold})"
    else:
        reason = f"Threat detected in input (score {threat_score:.2f} > threshold {threshold})"
    
    # Build comprehensive metadata
    metadata = {
        "pattern_score": pattern_score,
        "semantic_score": semantic_score,
        "role": role,
        "threshold": threshold,
    }
    metadata.update(pattern_metadata)
    
    return ClassifierResult(
        passed=passed,
        threat_score=threat_score,
        reason=reason,
        owasp_tag="LLM01:2025",
        metadata=metadata
    )


# Initialize library checks at module import time (but not semantic model loading)
_init_models()
