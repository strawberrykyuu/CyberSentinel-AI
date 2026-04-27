"""
agents/detection_agent.py
==========================
Detection Agent — multi-model anomaly scoring.

Responsibility
--------------
• Runs Isolation Forest, Z-Score, and UBA models in parallel.
• Combines their scores into a single unified anomaly_score.
• Annotates each event dict with:
    - anomaly_score  : float [0, 1]
    - is_anomaly     : bool
    - model_scores   : dict with per-model breakdown
• Forwards the annotated events to the Decision Agent.

Model fusion: weighted average
    anomaly_score = 0.40 * IF + 0.35 * ZScore + 0.25 * UBA
"""

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, clamp
from models.isolation_forest import IsolationForestDetector
from models.zscore import ZScoreDetector
from models.uba import UBADetector

logger = get_logger(__name__)

# Fusion weights (must sum to 1.0)
_W_IF     = 0.40
_W_ZSCORE = 0.35
_W_UBA    = 0.25

# Warm-up batch size before IF is reliably fitted
_WARMUP_SIZE = 50


class DetectionAgent:
    """
    Multi-model anomaly detector.

    Lifecycle
    ---------
    The first ``_WARMUP_SIZE`` events are used to warm-up the Isolation
    Forest model.  After that, all three models contribute to scoring.

    Call
    ----
    annotated_events = agent.process(cleaned_events)
    """

    def __init__(self):
        self._if_model     = IsolationForestDetector()
        self._zscore_model = ZScoreDetector()
        self._uba_model    = UBADetector()
        self._warmup_buffer: List[dict] = []
        self._if_ready     = False
        self._total_anomalies = 0
        self._total_processed = 0
        logger.info("DetectionAgent initialised (fusion weights IF=%.2f Z=%.2f UBA=%.2f).",
                    _W_IF, _W_ZSCORE, _W_UBA)

    # ------------------------------------------------------------------
    def _ensure_if_ready(self, events: List[dict]):
        """Accumulate events until IF has enough data to fit, then fit."""
        if self._if_ready:
            return
        self._warmup_buffer.extend(events)
        if len(self._warmup_buffer) >= _WARMUP_SIZE:
            self._if_model.fit(self._warmup_buffer)
            self._if_ready = True
            logger.info("IF model warm-up complete (%d events).", len(self._warmup_buffer))

    # ------------------------------------------------------------------
    def process(self, events: List[dict]) -> List[dict]:
        """
        Score each event with all three models and annotate.

        Parameters
        ----------
        events : validated events from MonitoringAgent

        Returns
        -------
        same list with anomaly_score / is_anomaly / model_scores filled in
        """
        if not events:
            return events

        self._ensure_if_ready(events)

        # Run all three models
        if_scores     = self._if_model.score(events)
        zscore_scores = self._zscore_model.score(events)
        uba_scores    = self._uba_model.score(events)

        annotated = []
        for i, ev in enumerate(events):
            if_s  = if_scores[i]
            zs    = zscore_scores[i]
            ub    = uba_scores[i]

            # Fusion
            combined = clamp(_W_IF * if_s + _W_ZSCORE * zs + _W_UBA * ub)

            # Known-bad IP → boost score
            if ev.get("known_bad_ip", False):
                combined = clamp(combined + 0.3)

            is_anomaly = combined >= config.ANOMALY_SCORE_THRESHOLD

            ev["anomaly_score"] = round(combined, 4)
            ev["is_anomaly"]    = is_anomaly
            ev["model_scores"]  = {
                "isolation_forest": round(if_s, 4),
                "zscore":           round(zs, 4),
                "uba":              round(ub, 4),
            }

            if is_anomaly:
                self._total_anomalies += 1

            annotated.append(ev)

        self._total_processed += len(events)
        anomaly_count = sum(1 for e in annotated if e["is_anomaly"])
        logger.info(
            "DetectionAgent: %d events, %d anomalies (total anomalies: %d).",
            len(events), anomaly_count, self._total_anomalies,
        )
        return annotated

    # ------------------------------------------------------------------
    @property
    def stats(self) -> dict:
        return {
            "total_processed": self._total_processed,
            "total_anomalies": self._total_anomalies,
            "if_ready":        self._if_ready,
        }
