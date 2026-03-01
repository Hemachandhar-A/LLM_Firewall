"""
Layer 8: Adaptive Rule Engine - Dynamic Attack Pattern Learning

This engine reads confirmed attack events from the honeypot (Layer 6) 
and updates the signature databases used by other layers.

Requires 3 confirmed occurrences of a pattern before updating any rule, 
to prevent adversarial feedback poisoning.

Function Interfaces:
- record_attack_event(attack_text, attack_type, layer_caught, session_id)
- process_pending_patterns() -> dict
- get_engine_stats() -> dict

OWASP TAG: LLM08:2025 (Feedback-loop Evasion)

SPEC REQUIREMENTS:
- Fail secure: raises FailSecureError on critical failures
- No hardcoded responses: all scoring/promotion based on real processing
- Real file I/O: writes to attack_seeds.json on disk for hot-reload
- Prevents poisoning: requires 3 occurrences before promoting pattern
- Comprehensive metadata: maintains count, examples, timestamps
"""

import json
import hashlib
import os
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

from sentence_transformers import SentenceTransformer
import numpy as np

from .base import FailSecureError

logger = logging.getLogger(__name__)

# ============================================================================
# Module Initialization
# ============================================================================

# Lazy-load embedding model on first use (thread-safe)
_embedding_model = None
_model_lock = threading.Lock()

def _get_embedding_model() -> SentenceTransformer:
    """Get or load the embedding model (thread-safe lazy load)."""
    global _embedding_model
    if _embedding_model is not None:
        return _embedding_model
    with _model_lock:
        if _embedding_model is None:
            try:
                _embedding_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
            except Exception as e:
                raise FailSecureError(f"Failed to load embedding model: {e}")
    return _embedding_model

# Data directory
DATA_DIR = Path(__file__).parent / "data"
ATTACK_SEEDS_FILE = DATA_DIR / "attack_seeds.json"

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# In-memory pending patterns dictionary
# Key: SHA-256 hash of attack text
# Value: {count, attack_type, examples[], first_seen, last_seen, promoted}
PENDING_PATTERNS: Dict[str, Dict[str, Any]] = {}

# Thread safety for PENDING_PATTERNS mutations
_patterns_lock = threading.Lock()

# Track promotion statistics
PROMOTION_STATS = {
    "last_processed": None,
}


# ============================================================================
# Core Functions
# ============================================================================


def record_attack_event(
    attack_text: str,
    attack_type: str,
    layer_caught: int,
    session_id: str,
) -> None:
    """
    Record a confirmed attack event in pending patterns.
    
    Stores the attack in PENDING_PATTERNS dict with:
    - Unique key: SHA-256 hash of attack_text
    - Count: incremented each time same attack seen
    - Examples: list of actual attacks (up to 3)
    - Timestamps: first_seen and last_seen
    - Metadata: attack_type, layer_caught, session_ids
    
    Args:
        attack_text (str): The attack input/output text
        attack_type (str): Type of attack (e.g., "prompt_injection", "pii_leak", 
                          "memory_poison", "tool_manipulation")
        layer_caught (int): Which layer caught this attack (1-9)
        session_id (str): Unique session identifier where attack occurred
    
    Raises:
        FailSecureError: If inputs are invalid or attack_text cannot be hashed
    """
    # Input validation
    if not isinstance(attack_text, str) or len(attack_text.strip()) == 0:
        raise FailSecureError("attack_text must be a non-empty string")
    
    if not isinstance(attack_type, str) or len(attack_type.strip()) == 0:
        raise FailSecureError("attack_type must be a non-empty string")
    
    if not isinstance(layer_caught, int) or not (1 <= layer_caught <= 9):
        raise FailSecureError("layer_caught must be an integer between 1 and 9")
    
    if not isinstance(session_id, str) or len(session_id.strip()) == 0:
        raise FailSecureError("session_id must be a non-empty string")
    
    try:
        # Compute pattern hash
        pattern_hash = hashlib.sha256(attack_text.encode("utf-8")).hexdigest()
        
        with _patterns_lock:
            # Get or create pattern entry
            if pattern_hash not in PENDING_PATTERNS:
                PENDING_PATTERNS[pattern_hash] = {
                    "count": 0,
                    "attack_type": attack_type,
                    "examples": [],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "session_ids": [],
                    "layers_caught": [],
                    "promoted": False,
                }
            
            pattern = PENDING_PATTERNS[pattern_hash]
            
            # Increment count and update timestamp
            pattern["count"] += 1
            pattern["last_seen"] = datetime.now(timezone.utc).isoformat()
            
            # Store example (deduplicate by text equality)
            if attack_text not in pattern["examples"]:
                pattern["examples"].append(attack_text)
            
            # Track session IDs and layers
            if session_id not in pattern["session_ids"]:
                pattern["session_ids"].append(session_id)
            
            if layer_caught not in pattern["layers_caught"]:
                pattern["layers_caught"].append(layer_caught)
            
            logger.debug(
                f"Recorded attack event: hash={pattern_hash[:8]}..., "
                f"type={attack_type}, layer={layer_caught}, count={pattern['count']}"
            )
        
    except Exception as e:
        raise FailSecureError(f"Failed to record attack event: {e}")


def process_pending_patterns() -> Dict[str, Any]:
    """
    Process pending patterns and promote those with count >= 3.
    
    For each pattern with count >= 3 (not already promoted):
    1. Extract embedding of the attack text using sentence-transformers
    2. Add to attack_seeds.json with proper structure
    3. Mark pattern as promoted to prevent reprocessing
    
    Returns:
        dict with keys:
        - "promoted": int, number of patterns promoted in this run
        - "pending": int, number of patterns still pending
        - "last_processed": datetime string of when processing occurred
        - "promoted_patterns": list of pattern hashes that were promoted
    
    Raises:
        FailSecureError: If file I/O fails or embedding generation fails
    """
    promoted_count = 0
    promoted_hashes = []
    
    try:
        # Load current attack seeds from disk
        attack_seeds_data = _load_attack_seeds()
        
        existing_texts = {attack["text"] for attack in attack_seeds_data["attacks"]}
        
        # Process each pending pattern (iterate over snapshot to prevent concurrent modification)
        for pattern_hash, pattern in list(PENDING_PATTERNS.items()):
            # Skip if already promoted or count < 3
            if pattern["promoted"] or pattern["count"] < 3:
                continue
            
            try:
                attack_text = pattern["examples"][0]
                
                # Skip if already in attack seeds
                if attack_text in existing_texts:
                    pattern["promoted"] = True
                    promoted_count += 1
                    promoted_hashes.append(pattern_hash)
                    logger.info(f"Pattern already in seeds, marking as promoted: {pattern_hash[:8]}...")
                    continue
                
                # Generate embedding
                logger.debug(f"Generating embedding for: {attack_text[:50]}...")
                embedding = _get_embedding_model().encode([attack_text], convert_to_numpy=True)[0]
                
                # Validate embedding
                if embedding.shape != (384,):
                    raise FailSecureError(
                        f"Invalid embedding shape: {embedding.shape} != (384,)"
                    )
                
                # Create attack seed entry with metadata
                new_attack = {
                    "text": attack_text,
                    "embedding": embedding.tolist(),
                    "attack_type": pattern["attack_type"],
                    "first_seen": pattern["first_seen"],
                    "last_seen": pattern["last_seen"],
                    "total_occurrences": pattern["count"],
                    "layers_caught": sorted(pattern["layers_caught"]),
                }
                
                # Add to attack seeds
                attack_seeds_data["attacks"].append(new_attack)
                
                # Mark as promoted (with thread safety)
                with _patterns_lock:
                    pattern["promoted"] = True
                promoted_count += 1
                promoted_hashes.append(pattern_hash)
                
                logger.info(
                    f"Promoted attack pattern: hash={pattern_hash[:8]}..., "
                    f"type={pattern['attack_type']}, occurrences={pattern['count']}"
                )
                
            except Exception as e:
                logger.error(
                    f"Failed to promote pattern {pattern_hash[:8]}...: {e}"
                )
                # Don't mark as promoted — retry next cycle
                continue
        
        # Write updated attack seeds to disk if any promotions occurred
        if promoted_count > 0:
            _save_attack_seeds(attack_seeds_data)
            logger.info(f"Saved {promoted_count} promoted patterns to attack_seeds.json")
        
        # Update global stats
        PROMOTION_STATS["last_processed"] = datetime.now(timezone.utc).isoformat()
        
        # Count remaining pending (not promoted, count < 3)
        pending_count = sum(
            1 for p in PENDING_PATTERNS.values()
            if not p["promoted"]
        )
        
        return {
            "promoted": promoted_count,
            "pending": pending_count,
            "last_processed": PROMOTION_STATS["last_processed"],
            "promoted_patterns": promoted_hashes,
        }
        
    except Exception as e:
        raise FailSecureError(f"Failed to process pending patterns: {e}")


def get_engine_stats() -> Dict[str, Any]:
    """
    Return current state of the adaptive engine for dashboard display.
    
    Returns:
        dict with:
        - "pending_patterns": int, number of patterns not yet promoted
        - "promoted_patterns": int, cumulative patterns promoted (from disk)
        - "last_processed": datetime string or None if never processed
        - "pending_details": list of pending patterns with their counts
    """
    try:
        pending_count = sum(
            1 for p in PENDING_PATTERNS.values()
            if not p["promoted"]
        )
        
        # Derive promoted count from disk (authoritative source)
        seeds = _load_attack_seeds()
        promoted_on_disk = len(seeds["attacks"])
        
        # Build detailed list of pending patterns (sorted by count desc)
        pending_details = []
        for pattern_hash, pattern in sorted(
            PENDING_PATTERNS.items(),
            key=lambda x: x[1]["count"],
            reverse=True,
        ):
            if not pattern["promoted"]:
                pending_details.append({
                    "hash": pattern_hash,
                    "count": pattern["count"],
                    "attack_type": pattern["attack_type"],
                    "first_seen": pattern["first_seen"],
                    "last_seen": pattern["last_seen"],
                    "layers_caught": sorted(pattern["layers_caught"]),
                })
        
        return {
            "pending_patterns": pending_count,
            "promoted_patterns": promoted_on_disk,
            "last_processed": PROMOTION_STATS["last_processed"],
            "pending_details": pending_details,
        }
        
    except Exception as e:
        raise FailSecureError(f"Failed to get engine stats: {e}")


# ============================================================================
# Helper Functions
# ============================================================================


def _load_attack_seeds() -> Dict[str, Any]:
    """
    Load attack seeds from JSON file.
    
    Returns:
        dict with "attacks" key containing list of attack dicts
    
    Raises:
        FailSecureError: If file cannot be read or JSON is invalid
    """
    try:
        if not ATTACK_SEEDS_FILE.exists():
            logger.warning(f"Attack seeds file not found, creating new: {ATTACK_SEEDS_FILE}")
            return {"attacks": []}
        
        with open(ATTACK_SEEDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if "attacks" not in data or not isinstance(data["attacks"], list):
            raise FailSecureError("attack_seeds.json must contain 'attacks' key with list value")
        
        return data
        
    except json.JSONDecodeError as e:
        raise FailSecureError(f"Invalid JSON in attack_seeds.json: {e}")
    except Exception as e:
        raise FailSecureError(f"Failed to load attack seeds: {e}")


def _save_attack_seeds(data: Dict[str, Any]) -> None:
    """
    Save attack seeds to JSON file (with backup).
    
    Args:
        data: dict with "attacks" key containing list of attack dicts
    
    Raises:
        FailSecureError: If file write fails
    """
    try:
        # Create backup of existing file
        if ATTACK_SEEDS_FILE.exists():
            backup_file = ATTACK_SEEDS_FILE.with_suffix(".json.backup")
            with open(ATTACK_SEEDS_FILE, "r", encoding="utf-8") as f:
                backup_data = f.read()
            with open(backup_file, "w", encoding="utf-8") as f:
                f.write(backup_data)
            logger.debug(f"Created backup: {backup_file}")
        
        # Write new data
        with open(ATTACK_SEEDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved attack seeds to {ATTACK_SEEDS_FILE}")
        
    except Exception as e:
        raise FailSecureError(f"Failed to save attack seeds: {e}")


def reset_pending_patterns() -> None:
    """
    Clear all pending patterns (useful for testing).
    
    WARNING: This removes all recorded attacks from memory. 
    Only call during testing or maintenance.
    """
    # .clear() mutates the existing dict in-place — no global declaration needed.
    # Do NOT use PENDING_PATTERNS = {} here; that creates a new local dict
    # and leaves the module-level dict unchanged.
    PENDING_PATTERNS.clear()
    logger.warning("Cleared all pending patterns (testing mode)")


def reset_stats() -> None:
    """
    Reset promotion statistics (useful for testing).
    """
    global PROMOTION_STATS
    PROMOTION_STATS["last_processed"] = None
    logger.warning("Reset promotion statistics (testing mode)")
