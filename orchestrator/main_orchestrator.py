"""
orchestrator/main_orchestrator.py
==================================
Main Orchestrator — the central controller that wires all agents together
and manages the event-driven decision flow.

Pipeline
--------
  Simulator → MonitoringAgent
            → DetectionAgent
            → DecisionAgent
                ├─ file_threats  → MalwareAgent → ResponseAgent
                └─ other_threats → ResponseAgent

The orchestrator does NOT contain business logic.  It only:
  1. Instantiates all agents once.
  2. Routes batches of events through the pipeline in order.
  3. Accumulates a session history list for the UI.
  4. Exposes aggregate statistics.
"""

import os
import sys
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger
from data.simulator import EventSimulator
from agents.monitoring_agent import MonitoringAgent
from agents.detection_agent  import DetectionAgent
from agents.decision_agent   import DecisionAgent
from agents.malware_agent    import MalwareAgent
from agents.response_agent   import ResponseAgent

logger = get_logger(__name__)

# Maximum number of events kept in memory for the UI history
_MAX_HISTORY = 2000


class MainOrchestrator:
    """
    Central controller for the cybersecurity AI pipeline.

    Usage (batch mode)
    ------------------
    orc = MainOrchestrator()
    orc.run(max_batches=5)
    print(orc.history[-1])   # inspect last processed event

    Usage (single-batch — used by the Streamlit UI)
    -------------------------------------------------
    orc = MainOrchestrator()
    new_events = orc.tick()   # process one batch, return finalised events
    """

    def __init__(self):
        logger.info("=== Initialising MainOrchestrator ===")
        self.simulator        = EventSimulator()
        self.monitoring_agent = MonitoringAgent()
        self.detection_agent  = DetectionAgent()
        self.decision_agent   = DecisionAgent()
        self.malware_agent    = MalwareAgent()
        self.response_agent   = ResponseAgent()

        # Accumulated history for UI / analysis
        self.history: List[dict] = []
        self._batch_count = 0
        logger.info("MainOrchestrator ready.")

    # ------------------------------------------------------------------
    def _pipeline(self, raw_events: List[dict]) -> List[dict]:
        """
        Run one batch through the full agent pipeline.

        Returns the list of fully finalised event dicts.
        """
        # Stage 1 — Monitoring
        cleaned = self.monitoring_agent.process(raw_events)
        if not cleaned:
            return []

        # Stage 2 — Detection
        detected = self.detection_agent.process(cleaned)

        # Stage 3 — Decision  (returns two streams)
        file_threats, other_threats = self.decision_agent.process(detected)

        # Stage 4a — Malware analysis (file threats only)
        malware_enriched: List[dict] = []
        if file_threats:
            malware_enriched = self.malware_agent.process(file_threats)

        # Stage 4b — Response (all events)
        all_events = malware_enriched + other_threats
        finalised  = self.response_agent.process(all_events)

        return finalised

    # ------------------------------------------------------------------
    def tick(self) -> List[dict]:
        """
        Pull one batch from the simulator, run the pipeline, return results.
        This is called by the Streamlit UI on every auto-refresh cycle.
        """
        raw = self.simulator.next_batch()
        finalised = self._pipeline(raw)

        # Append to history (bounded)
        self.history.extend(finalised)
        if len(self.history) > _MAX_HISTORY:
            self.history = self.history[-_MAX_HISTORY:]

        self._batch_count += 1
        return finalised

    # ------------------------------------------------------------------
    def run(
        self,
        max_batches: int = 10,
        verbose: bool = True,
    ) -> List[dict]:
        """
        Run multiple batches (CLI / testing mode).

        Parameters
        ----------
        max_batches : number of batches to process
        verbose     : print a summary after each batch

        Returns
        -------
        flat list of all finalised events
        """
        all_results: List[dict] = []
        logger.info("Starting run: %d batches.", max_batches)

        for batch_num in range(1, max_batches + 1):
            finalised = self.tick()
            all_results.extend(finalised)

            if verbose:
                anomalies = sum(1 for e in finalised if e.get("is_anomaly"))
                blocked   = sum(1 for e in finalised if e.get("is_blocked"))
                print(
                    f"Batch {batch_num:3d}/{max_batches} | "
                    f"events={len(finalised):3d} | "
                    f"anomalies={anomalies:3d} | "
                    f"blocked={blocked}"
                )

        logger.info("Run complete. Total events: %d.", len(all_results))
        return all_results

    # ------------------------------------------------------------------
    @property
    def stats(self) -> Dict[str, Any]:
        """Aggregate statistics from all agents."""
        return {
            "batches_processed":  self._batch_count,
            "history_size":       len(self.history),
            "monitoring":         self.monitoring_agent.stats,
            "detection":          self.detection_agent.stats,
            "decision_severity":  self.decision_agent.severity_counts,
            "malware":            self.malware_agent.stats,
            "response_actions":   self.response_agent.action_counts,
            "blocked_ips":        list(self.response_agent.blocked_ips),
            "isolated_hosts":     list(self.response_agent.isolated_hosts),
        }
