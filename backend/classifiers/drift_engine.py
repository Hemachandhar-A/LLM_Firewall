"""
Layer 4: Semantic Drift Velocity Engine

Tracks the trajectory of a conversation through semantic space and detects
when the conversation is accelerating toward known attack patterns.

Functions:
- embed_turn(text): Convert text to 384-dim embedding vector
- compute_drift_velocity(session_id, text): Track drift and compute threat
- reset_session(session_id): Clear session history

OWASP tag: "LLM04:2025"
"""

import json
import pickle
import os
import logging
import numpy as np
from typing import Dict, List

from .base import ClassifierResult, FailSecureError

logger = logging.getLogger(__name__)

# Graceful degradation for heavy ML libs
_ml_available = False

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_distances
    _ml_available = True
except ImportError:
    logger.warning("sentence-transformers/sklearn not available — drift engine disabled")


# ============================================================================
# Module Initialization
# ============================================================================

MODEL = None
CLUSTER_CENTROIDS = {}
UMAP_MODEL = None

if _ml_available:
    # Load model once at import time
    try:
        MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    except Exception as e:
        logger.warning(f"Failed to load sentence-transformers model: {e}")
        _ml_available = False

# Load cluster centroids from JSON
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CLUSTER_CENTROIDS_FILE = os.path.join(DATA_DIR, "cluster_centroids.json")

try:
    with open(CLUSTER_CENTROIDS_FILE, "r") as f:
        centroids_data = json.load(f)
    CLUSTER_CENTROIDS = {
        cluster_name: np.array(centroid, dtype=np.float32)
        for cluster_name, centroid in centroids_data.items()
    }
except Exception as e:
    logger.warning(f"Failed to load cluster centroids: {e}")

# Load or fit UMAP model
UMAP_MODEL_FILE = os.path.join(DATA_DIR, "umap_model.pkl")

if _ml_available:
    try:
        if os.path.exists(UMAP_MODEL_FILE) and os.path.getsize(UMAP_MODEL_FILE) > 0:
            with open(UMAP_MODEL_FILE, "rb") as f:
                UMAP_MODEL = pickle.load(f)
        else:
            from umap import UMAP

            centroid_vectors = np.array(
                [centroid for centroid in CLUSTER_CENTROIDS.values()],
                dtype=np.float32,
            )

            UMAP_MODEL = UMAP(n_components=2, random_state=42, min_dist=0.1)
            UMAP_MODEL.fit(centroid_vectors)

            os.makedirs(DATA_DIR, exist_ok=True)
            with open(UMAP_MODEL_FILE, "wb") as f:
                pickle.dump(UMAP_MODEL, f)

    except Exception as e:
        logger.warning(f"Failed to load/fit UMAP model: {e}")
        _ml_available = False

# In-memory session history: session_id -> list of dicts with turn data
SESSION_HISTORY: Dict[str, List[Dict]] = {}


# ============================================================================
# Core Functions
# ============================================================================


def embed_turn(text: str) -> np.ndarray:
    """
    Embed a single turn of conversation text.
    Returns a 384-dim numpy array, or a zero vector if ML libs are unavailable.
    """
    if not _ml_available or MODEL is None:
        # Return zero vector so callers expecting ndarray don't break
        return np.zeros(384, dtype=np.float32)

    if not isinstance(text, str):
        raise FailSecureError(f"embed_turn requires str input, got {type(text)}")

    try:
        embedding = MODEL.encode(text, convert_to_numpy=True)
        if embedding.shape[0] != 384:
            raise FailSecureError(
                f"Expected 384-dim embedding, got {embedding.shape[0]}"
            )
        return embedding.astype(np.float32)
    except Exception as e:
        raise FailSecureError(f"Failed to embed turn: {e}")


def compute_drift_velocity(session_id: str, text: str) -> ClassifierResult:
    """
    Compute semantic drift velocity for a conversation turn.

    Tracks how fast the conversation is moving toward threat cluster centroids.
    Updates session history and returns risk assessment with 2D visualization
    coordinates.

    Args:
        session_id (str): Unique session identifier
        text (str): The user's message for this turn

    Returns:
        ClassifierResult with:
            - passed: True if cumulative_risk < 0.6 AND velocity < 0.3
            - passed: False if cumulative_risk > 0.7 OR velocity > 0.4
            - threat_score: cumulative_risk (mean of last 5 threat_proximity)
            - metadata: {
                "velocity": float,
                "nearest_cluster": str,
                "x_coord": float (UMAP x),
                "y_coord": float (UMAP y),
                "turn_number": int,
                "session_vector_history": list of last 5 threat_proximity values
              }

    Raises:
        FailSecureError: If computation fails
    """
    # Graceful degradation: if ML libs unavailable, pass through
    if not _ml_available or MODEL is None:
        return ClassifierResult(
            passed=True, threat_score=0.0,
            reason="Drift engine unavailable (ML libs not installed)",
            owasp_tag="LLM04:2025",
            metadata={"velocity": 0.0, "nearest_cluster": "unknown",
                       "x_coord": 0.0, "y_coord": 0.0, "turn_number": 0,
                       "session_vector_history": []}
        )

    try:
        # Embed the current turn
        embedding = embed_turn(text)

        # Initialize session history if needed
        if session_id not in SESSION_HISTORY:
            SESSION_HISTORY[session_id] = []

        # Compute cosine distance to each cluster centroid
        distances = {}
        for cluster_name, centroid in CLUSTER_CENTROIDS.items():
            # cosine_distances returns [[distance]]
            distance = float(
                cosine_distances([embedding], [centroid])[0][0]
            )
            distances[cluster_name] = distance

        # Find nearest cluster
        nearest_cluster = min(distances.keys(), key=lambda c: distances[c])
        nearest_distance = distances[nearest_cluster]

        # Compute threat proximity (0=far from threat, 1=at threat)
        threat_proximity = 1.0 - nearest_distance

        # Compute velocity (change from previous turn)
        if len(SESSION_HISTORY[session_id]) == 0:
            velocity = 0.0
        else:
            previous_threat_proximity = SESSION_HISTORY[session_id][-1][
                "threat_proximity"
            ]
            velocity = threat_proximity - previous_threat_proximity

        # Store this turn's data
        turn_data = {
            "threat_proximity": threat_proximity,
            "velocity": velocity,
            "nearest_cluster": nearest_cluster,
            "embedding": embedding,
        }
        SESSION_HISTORY[session_id].append(turn_data)

        # Compute cumulative risk: mean of last 5 threat_proximity values
        history_window = SESSION_HISTORY[session_id][-5:]
        threat_proximities = [turn["threat_proximity"] for turn in history_window]
        cumulative_risk = float(np.mean(threat_proximities))

        # Project embedding to 2D using UMAP for dashboard
        coords_2d = UMAP_MODEL.transform([embedding])[0]
        x_coord = float(coords_2d[0])
        y_coord = float(coords_2d[1])

        # Decision logic
        if cumulative_risk < 0.6 and velocity < 0.3:
            passed = True
        elif cumulative_risk > 0.7 or velocity > 0.4:
            passed = False
        else:
            # In-between range: be conservative
            passed = cumulative_risk < 0.65

        # Build metadata
        metadata = {
            "velocity": velocity,
            "nearest_cluster": nearest_cluster,
            "x_coord": x_coord,
            "y_coord": y_coord,
            "turn_number": len(SESSION_HISTORY[session_id]),
            "session_vector_history": threat_proximities,
        }

        reason = (
            f"Drift velocity engine: cumulative_risk={cumulative_risk:.3f}, "
            f"velocity={velocity:.3f}, nearest_cluster={nearest_cluster}"
        )

        return ClassifierResult(
            passed=passed,
            threat_score=cumulative_risk,
            reason=reason,
            owasp_tag="LLM04:2025",
            metadata=metadata,
        )

    except FailSecureError:
        raise
    except Exception as e:
        raise FailSecureError(f"compute_drift_velocity failed: {e}")


def reset_session(session_id: str) -> None:
    """
    Clear session history when a session ends.

    Args:
        session_id (str): Session to clear
    """
    if session_id in SESSION_HISTORY:
        del SESSION_HISTORY[session_id]
