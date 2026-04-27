"""
models/zscore.py
================
Rolling Z-Score anomaly detector.

For each numeric feature it maintains a rolling window of recent values
and flags a sample if *any* feature's |z-score| exceeds the threshold.

The combined anomaly score is the max normalised z-score across all
features (capped to 1.0).
"""

import os
import sys
import numpy as np
from collections import deque
from typing import List, Dict, Deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, clamp

logger = get_logger(__name__)

FEATURE_KEYS = [
    "bytes_sent",
    "bytes_received",
    "duration_sec",
    "num_connections",
    "failed_logins",
    "port",
]


class ZScoreDetector:
    """
    Maintains per-feature rolling windows and computes z-scores.

    The window size is config.ZSCORE_ROLLING_WINDOW.
    Threshold is config.ZSCORE_THRESHOLD.
    """

    def __init__(self):
        self._window_size = config.ZSCORE_ROLLING_WINDOW
        self._threshold   = config.ZSCORE_THRESHOLD
        # Per-feature rolling window (deque)
        self._windows: Dict[str, Deque[float]] = {
            k: deque(maxlen=self._window_size) for k in FEATURE_KEYS
        }
        logger.info(
            "ZScoreDetector created (window=%d, threshold=%.1f)",
            self._window_size, self._threshold,
        )

    # ------------------------------------------------------------------
    def _z_score(self, key: str, value: float) -> float:
        """
        Compute z = (value - mean) / std using the current window.
        Returns 0.0 if the window has fewer than 2 points.
        """
        buf = self._windows[key]
        if len(buf) < 2:
            return 0.0
        arr = np.array(buf, dtype=np.float64)
        std = arr.std()
        if std < 1e-9:
            return 0.0
        return (value - arr.mean()) / std

    # ------------------------------------------------------------------
    def _update_and_score_event(self, event: dict) -> float:
        """
        Update windows with the event's features, return anomaly score.
        """
        rf = event.get("raw_features", {})
        max_z = 0.0
        for key in FEATURE_KEYS:
            value = float(rf.get(key, 0))
            z = abs(self._z_score(key, value))
            max_z = max(max_z, z)
            self._windows[key].append(value)   # update AFTER scoring

        # Normalise: z / threshold → 1.0 means exactly at threshold
        # Values above threshold map to > 1.0, which we clamp.
        normalised = clamp(max_z / self._threshold)
        return normalised

    # ------------------------------------------------------------------
    def score(self, events: List[dict]) -> List[float]:
        """
        Score a batch of events.  Processes them in order so each event
        is scored against the window built from previous events.

        Returns anomaly scores in [0, 1].
        """
        scores = []
        for ev in events:
            s = self._update_and_score_event(ev)
            scores.append(s)
        return scores

    # ------------------------------------------------------------------
    def predict(self, events: List[dict]) -> List[bool]:
        """Return True where z-score anomaly is detected."""
        return [s >= 1.0 for s in self.score(events)]

    # ------------------------------------------------------------------
    def reset(self):
        """Clear all rolling windows (useful between simulation runs)."""
        for key in FEATURE_KEYS:
            self._windows[key].clear()
        logger.info("ZScoreDetector windows cleared.")
