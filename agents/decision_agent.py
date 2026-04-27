"""
agents/decision_agent.py
========================
Decision Agent — classifies each anomalous event by severity and decides
what action path to take.

Responsibility
--------------
• Receives annotated events from the Detection Agent.
• Assigns a severity label: low / medium / high / critical.
• Determines the decision: monitor / alert / block / isolate.
• Flags file-related events for deeper analysis by the Malware Agent.
• Passes results to:
    - MalwareAgent   (if is_file_threat == True)
    - ResponseAgent  (always, after optional malware analysis)

Decision logic
--------------
┌─────────────────────┬──────────────┬──────────────────────────┐
│ Score range         │ Severity     │ Decision                 │
├─────────────────────┼──────────────┼──────────────────────────┤
│ < ANOMALY_THRESHOLD │ low          │ log_and_monitor          │
│ [0.50 – 0.75)       │ medium       │ alert_and_throttle       │
│ [0.75 – 0.90)       │ high         │ block_ip + file check    │
│ ≥ 0.90              │ critical     │ isolate_host             │
└─────────────────────┴──────────────┴──────────────────────────┘
"""

import os
import sys
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, severity_label

logger = get_logger(__name__)

# Event types that warrant a file / malware analysis pass
_FILE_RELATED_EVENT_TYPES = {
    "file_access",
    "data_exfiltration",
    "ransomware_activity",
    "malware_download",
    "suspicious_write",
}


class DecisionAgent:
    """
    Applies decision logic to each event and routes it accordingly.

    Call
    ----
    file_threats, normal_threats = agent.process(detected_events)

    Returns
    -------
    file_threats   : events that need MalwareAgent analysis
    normal_threats : events going straight to ResponseAgent
    """

    def __init__(self):
        self._counts = {s: 0 for s in ("low", "medium", "high", "critical")}
        logger.info("DecisionAgent initialised.")

    # ------------------------------------------------------------------
    def _decide(self, event: dict) -> Tuple[str, str, bool]:
        """
        Compute (severity, decision, is_file_threat) for one event.
        """
        score = event.get("anomaly_score", 0.0)
        sev   = severity_label(score)
        dec   = config.RESPONSE_ACTIONS.get(sev, "log_and_monitor")

        # Determine if a file-level investigation is needed
        is_file_threat = (
            event.get("event_type", "") in _FILE_RELATED_EVENT_TYPES
            and score >= config.HIGH_SEVERITY_THRESHOLD
        )

        return sev, dec, is_file_threat

    # ------------------------------------------------------------------
    def process(
        self, events: List[dict]
    ) -> Tuple[List[dict], List[dict]]:
        """
        Annotate each event with severity / decision / is_file_threat.

        Parameters
        ----------
        events : events from DetectionAgent (with anomaly_score)

        Returns
        -------
        (file_threats, normal_threats)
        """
        file_threats   = []
        normal_threats = []

        for ev in events:
            sev, dec, is_file = self._decide(ev)
            ev["severity"]       = sev
            ev["decision"]       = dec
            ev["is_file_threat"] = is_file

            self._counts[sev] += 1

            if is_file:
                file_threats.append(ev)
                logger.info(
                    "File threat detected: %s | score=%.3f | sev=%s | action=%s",
                    ev.get("source_ip"), ev.get("anomaly_score"), sev, dec,
                )
            else:
                normal_threats.append(ev)

        if file_threats or any(ev.get("anomaly_score", 0) >= config.ANOMALY_SCORE_THRESHOLD
                                for ev in normal_threats):
            logger.info(
                "DecisionAgent: %d file threats, %d direct threats.",
                len(file_threats), len(normal_threats),
            )

        return file_threats, normal_threats

    # ------------------------------------------------------------------
    @property
    def severity_counts(self) -> dict:
        return dict(self._counts)
