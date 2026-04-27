"""
models/uba.py
=============
User Behaviour Analytics (UBA) model.

Maintains per-user behavioural profiles over a sliding event window and
flags users who deviate from their own baseline.

Rules implemented
-----------------
1. Excessive failed logins     (>= UBA_MAX_FAILED_LOGINS per window)
2. Access from too many IPs    (>= UBA_MAX_DISTINCT_IPS per window)
3. Rare event type for user    (event type seen < 5% of the time for that user)

Combined anomaly score = weighted sum of rule violations in [0, 1].
"""

import os
import sys
from collections import defaultdict, deque
from typing import List, Dict, Deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, clamp

logger = get_logger(__name__)


class _UserProfile:
    """Sliding-window profile for a single user."""

    def __init__(self, window: int):
        self._window = window
        self.failed_logins:  Deque[int]   = deque(maxlen=window)
        self.source_ips:     Deque[str]   = deque(maxlen=window)
        self.event_types:    Deque[str]   = deque(maxlen=window)

    def update(self, event: dict):
        rf = event.get("raw_features", {})
        self.failed_logins.append(int(rf.get("failed_logins", 0)))
        self.source_ips.append(event.get("source_ip", "0.0.0.0"))
        self.event_types.append(event.get("event_type", "unknown"))

    # ----------------------------------------------------------------
    def failed_login_score(self) -> float:
        total = sum(self.failed_logins)
        return clamp(total / config.UBA_MAX_FAILED_LOGINS)

    def ip_diversity_score(self) -> float:
        distinct = len(set(self.source_ips))
        return clamp(distinct / config.UBA_MAX_DISTINCT_IPS)

    def rare_event_score(self, current_event_type: str) -> float:
        if not self.event_types:
            return 0.0
        freq = self.event_types.count(current_event_type) / len(self.event_types)
        # Rarity = 1 - frequency; scale so freq < 5% → score > 0
        return clamp(1.0 - freq * 20)  # * 20 so 5% → 0, 0% → 1


class UBADetector:
    """
    Maintains per-user profiles and scores each event against the user's
    own behavioural baseline.
    """

    def __init__(self):
        self._profiles: Dict[str, _UserProfile] = defaultdict(
            lambda: _UserProfile(config.UBA_LOOKBACK_ROWS)
        )
        logger.info(
            "UBADetector created (window=%d, max_failed=%d, max_ips=%d)",
            config.UBA_LOOKBACK_ROWS,
            config.UBA_MAX_FAILED_LOGINS,
            config.UBA_MAX_DISTINCT_IPS,
        )

    # ------------------------------------------------------------------
    def score(self, events: List[dict]) -> List[float]:
        """
        Score a batch of events.  Each event is scored then the profile
        is updated — so the score reflects the user's *past* behaviour.

        Returns anomaly scores in [0, 1].
        """
        scores = []
        for ev in events:
            user = ev.get("user", "unknown")
            profile = self._profiles[user]

            # Score BEFORE updating (so we judge against past history)
            fl_score    = profile.failed_login_score()
            ip_score    = profile.ip_diversity_score()
            rare_score  = profile.rare_event_score(ev.get("event_type", "unknown"))

            # Weighted combination
            combined = clamp(0.4 * fl_score + 0.4 * ip_score + 0.2 * rare_score)
            scores.append(combined)

            # Update profile with current event
            profile.update(ev)

        return scores

    # ------------------------------------------------------------------
    def predict(self, events: List[dict]) -> List[bool]:
        """Return True where UBA flags anomalous behaviour."""
        return [s >= config.ANOMALY_SCORE_THRESHOLD for s in self.score(events)]

    # ------------------------------------------------------------------
    def profile_summary(self, user: str) -> dict:
        """Return a human-readable summary of a user's current profile."""
        if user not in self._profiles:
            return {"user": user, "status": "no data"}
        p = self._profiles[user]
        return {
            "user":           user,
            "failed_logins":  sum(p.failed_logins),
            "distinct_ips":   len(set(p.source_ips)),
            "event_count":    len(p.event_types),
        }
