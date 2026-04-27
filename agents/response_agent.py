"""
agents/response_agent.py
========================
Response Agent — executes (or simulates) remediation actions and
produces the final enriched event record that is stored / displayed.

Responsibility
--------------
• Receives all events (after optional malware enrichment).
• Executes the response action determined by the Decision Agent:
    low      → log_and_monitor   : write to log only
    medium   → alert_and_throttle: log + rate-limit the source IP
    high     → block_ip          : add to blocked-IP set
    critical → isolate_host      : add to isolated-host set
• Records the final response in each event dict.
• Maintains a live block-list and isolation list.
• Returns fully finalised event records for the UI / storage layer.
"""

import os
import sys
from datetime import datetime, timezone
from typing import List, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger

logger = get_logger(__name__)


class ResponseAgent:
    """
    Executes response actions and finalises event records.

    Call
    ----
    final_events = agent.process(events_after_decision_and_malware)
    """

    def __init__(self):
        self._blocked_ips:     Set[str] = set()
        self._isolated_hosts:  Set[str] = set()
        self._throttled_ips:   Set[str] = set()
        self._action_counts = {action: 0 for action in config.RESPONSE_ACTIONS.values()}
        logger.info("ResponseAgent initialised.")

    # ------------------------------------------------------------------
    def _execute(self, event: dict) -> str:
        """
        Execute the response action for an event.
        Returns a human-readable description of what was done.
        """
        action  = event.get("decision", "log_and_monitor")
        src_ip  = event.get("source_ip", "unknown")
        user    = event.get("user", "unknown")
        sev     = event.get("severity", "low")

        if action == "log_and_monitor":
            msg = f"Event logged and queued for monitoring."

        elif action == "alert_and_throttle":
            self._throttled_ips.add(src_ip)
            msg = (
                f"Alert raised for {src_ip}. "
                f"Traffic throttled. SOC notified (simulated)."
            )

        elif action == "block_ip":
            self._blocked_ips.add(src_ip)
            self._throttled_ips.discard(src_ip)
            msg = (
                f"IP {src_ip} BLOCKED. "
                f"Firewall rule applied (simulated). "
                f"User '{user}' session terminated."
            )
            logger.warning("BLOCK: %s | user=%s | severity=%s", src_ip, user, sev)

        elif action == "isolate_host":
            self._isolated_hosts.add(src_ip)
            self._blocked_ips.add(src_ip)
            msg = (
                f"HOST {src_ip} ISOLATED from network. "
                f"Incident ticket created (simulated). "
                f"Forensic collection queued."
            )
            logger.error("ISOLATE: %s | user=%s | malware=%s",
                         src_ip, user, event.get("malware_label", "n/a"))
        else:
            msg = f"Unknown action '{action}'; defaulting to log."
            action = "log_and_monitor"

        self._action_counts[action] = self._action_counts.get(action, 0) + 1
        return msg

    # ------------------------------------------------------------------
    def process(self, events: List[dict]) -> List[dict]:
        """
        Execute responses and annotate each event with response details.

        Parameters
        ----------
        events : events from DecisionAgent / MalwareAgent

        Returns
        -------
        fully annotated event records ready for storage / UI
        """
        finalised = []
        for ev in events:
            response_msg = self._execute(ev)
            ev["response_action"]  = ev.get("decision", "log_and_monitor")
            ev["response_message"] = response_msg
            ev["response_time"]    = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            ev["is_blocked"]   = ev.get("source_ip") in self._blocked_ips
            ev["is_isolated"]  = ev.get("source_ip") in self._isolated_hosts
            finalised.append(ev)

        blocked_new = sum(1 for e in finalised if e.get("is_blocked"))
        if blocked_new:
            logger.info("ResponseAgent: %d events processed, %d blocked.",
                        len(finalised), blocked_new)

        return finalised

    # ------------------------------------------------------------------
    @property
    def blocked_ips(self) -> Set[str]:
        return frozenset(self._blocked_ips)

    @property
    def isolated_hosts(self) -> Set[str]:
        return frozenset(self._isolated_hosts)

    @property
    def action_counts(self) -> dict:
        return dict(self._action_counts)
