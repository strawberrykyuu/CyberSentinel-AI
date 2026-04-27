"""
models/isolation_forest.py
===========================
Isolation Forest anomaly detector.

Isolation Forest works by randomly partitioning the feature space and
measuring how many splits it takes to isolate a point.  Anomalies are
isolated quickly (short paths) and therefore get high anomaly scores.

This wrapper:
  - Accepts a list of event dicts and extracts numeric features.
  - Trains on a warm-up window, then scores new events online.
  - Returns anomaly_score in [0, 1] (1 = most anomalous).
"""

import os
import sys
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, clamp

logger = get_logger(__name__)

# Numeric feature keys extracted from event["raw_features"]
FEATURE_KEYS = [
    "bytes_sent",
    "bytes_received",
    "duration_sec",
    "num_connections",
    "failed_logins",
    "port",
]


def _extract_features(events: List[dict]) -> np.ndarray:
    """Extract a 2-D float32 matrix from a list of event dicts."""
    rows = []
    for ev in events:
        rf = ev.get("raw_features", {})
        row = [float(rf.get(k, 0)) for k in FEATURE_KEYS]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


class IsolationForestDetector:
    """
    Wraps sklearn IsolationForest with a simple online interface.

    Lifecycle
    ---------
    1. Collect a warm-up batch via ``fit(events)``.
    2. Score any subsequent events via ``score(events)``.
    """

    def __init__(self):
        self._model = IsolationForest(
            n_estimators=config.IF_N_ESTIMATORS,
            contamination=config.IF_CONTAMINATION,
            max_samples=config.IF_MAX_SAMPLES,
            random_state=config.IF_RANDOM_STATE,
            n_jobs=-1,
        )
        self._fitted = False
        logger.info(
            "IsolationForestDetector created (n_estimators=%d, contamination=%.2f)",
            config.IF_N_ESTIMATORS,
            config.IF_CONTAMINATION,
        )

    # ------------------------------------------------------------------
    def fit(self, events: List[dict]) -> "IsolationForestDetector":
        """
        Train the model on a batch of events.  Can be called multiple
        times to retrain on fresh data.
        """
        X = _extract_features(events)
        if X.shape[0] < 2:
            logger.warning("IF: need at least 2 samples to fit; skipping.")
            return self
        self._model.fit(X)
        self._fitted = True
        logger.info("IF model fitted on %d samples.", X.shape[0])
        return self

    # ------------------------------------------------------------------
    def score(self, events: List[dict]) -> List[float]:
        """
        Return a list of anomaly scores in [0, 1] for each event.
        0 = normal, 1 = very anomalous.

        If the model has not been fitted yet it trains on the same events
        (cold-start behaviour) and returns preliminary scores.
        """
        X = _extract_features(events)
        if not self._fitted:
            logger.warning("IF cold-start: fitting on incoming batch.")
            self.fit(events)

        # sklearn returns -1 (anomaly) or +1 (normal) for predict,
        # and negative scores from decision_function (lower = more anomalous).
        raw_scores = self._model.decision_function(X)  # shape (n,)

        # Normalise to [0, 1]:  more negative → closer to 1
        lo, hi = raw_scores.min(), raw_scores.max()
        if hi == lo:
            normalised = [0.5] * len(events)
        else:
            normalised = [(hi - s) / (hi - lo) for s in raw_scores]

        return [clamp(s) for s in normalised]

    # ------------------------------------------------------------------
    def predict(self, events: List[dict]) -> List[bool]:
        """Return True where the model predicts anomaly."""
        scores = self.score(events)
        return [s >= config.ANOMALY_SCORE_THRESHOLD for s in scores]
