"""
agents/monitoring_agent.py
==========================
Monitoring Agent — the entry point of the pipeline.

Responsibility
--------------
• Receives raw event batches from the simulator.
• Performs lightweight pre-processing: type coercion, field validation,
  deduplication, and basic enrichment (e.g. flagging known-bad IPs).
• Forwards a clean, validated list of event dicts to the Detection Agent.

It does NOT make any anomaly decisions — it only prepares the data.
"""

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, utc_now_str, clamp

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Known-bad IP block-list (demo; extend as needed)
# ---------------------------------------------------------------------------
_KNOWN_BAD_IPS = {
    "10.0.0.99",
    "172.16.0.200",
    "203.0.113.5",
    "198.51.100.1",
}

_REQUIRED_FEATURE_KEYS = [
    "bytes_sent",
    "bytes_received",
    "duration_sec",
    "num_connections",
    "failed_logins",
    "port",
]


class MonitoringAgent:
    """
    First agent in the pipeline.

    Call
    ----
    cleaned_events = agent.process(raw_events)
    """

    def __init__(self):
        self._seen_hashes = set()          # simple dedup window
        self._total_received = 0
        self._total_forwarded = 0
        logger.info("MonitoringAgent initialised.")

    # ------------------------------------------------------------------
    def _validate_and_clean(self, event: dict) -> dict:
        """
        Ensure required fields are present and have the right types.
        Also enriches the event with a 'known_bad_ip' flag.
        """
        # Ensure top-level string fields
        for field in ("source_ip", "dest_ip", "user", "event_type"):
            event.setdefault(field, "unknown")
            event[field] = str(event[field]).strip() or "unknown"

        # Ensure timestamp
        event.setdefault("timestamp", utc_now_str())

        # Ensure numeric features
        rf = event.setdefault("raw_features", {})
        for key in _REQUIRED_FEATURE_KEYS:
            try:
                rf[key] = float(rf.get(key, 0) or 0)
            except (TypeError, ValueError):
                rf[key] = 0.0

        # Clamp port to valid range
        rf["port"] = clamp(rf["port"], 0, 65535)

        # Enrichment: flag known-bad source IPs
        event["known_bad_ip"] = event["source_ip"] in _KNOWN_BAD_IPS

        return event

    # ------------------------------------------------------------------
    def _dedup_key(self, event: dict) -> str:
        """A lightweight dedup fingerprint (src + dst + type + bytes)."""
        rf = event.get("raw_features", {})
        return (
            f"{event['source_ip']}|{event['dest_ip']}|"
            f"{event['event_type']}|{rf.get('bytes_sent', 0)}"
        )

    # ------------------------------------------------------------------
    def process(self, raw_events: List[dict]) -> List[dict]:
        """
        Validate, enrich, and deduplicate a batch of raw events.

        Parameters
        ----------
        raw_events : list of raw event dicts from the simulator

        Returns
        -------
        list of cleaned event dicts ready for the Detection Agent
        """
        self._total_received += len(raw_events)
        cleaned = []

        for event in raw_events:
            try:
                clean_event = self._validate_and_clean(event)
            except Exception as exc:
                logger.warning("Skipping malformed event: %s", exc)
                continue

            # Deduplication (keep a rolling set of 1000 recent keys)
            key = self._dedup_key(clean_event)
            if key in self._seen_hashes:
                logger.debug("Duplicate event dropped: %s", key)
                continue
            self._seen_hashes.add(key)
            if len(self._seen_hashes) > 1000:
                # Remove oldest entry (sets don't maintain order, so we
                # just remove a random one — acceptable for dedup)
                self._seen_hashes.pop()

            cleaned.append(clean_event)

        self._total_forwarded += len(cleaned)
        logger.info(
            "MonitoringAgent: %d in → %d forwarded (total: %d/%d)",
            len(raw_events), len(cleaned),
            self._total_forwarded, self._total_received,
        )
        return cleaned

    # ------------------------------------------------------------------
    @property
    def stats(self) -> dict:
        return {
            "total_received":  self._total_received,
            "total_forwarded": self._total_forwarded,
        }
