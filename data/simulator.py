"""
data/simulator.py
=================
Simulates a stream of security log events.

Two modes
---------
1. CSV mode   — reads from the Kaggle dataset (config.DATASET_PATH).
2. Synthetic  — generates realistic-looking random events when no CSV
                is present (useful for first-run / demo).

The simulator yields batches of event dicts (see utils.helpers.make_event)
so the orchestrator can call it in a loop.
"""

import os
import random
import time
import numpy as np
import pandas as pd
from typing import Generator, List

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.helpers import get_logger, make_event, utc_now_str

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Internal synthetic-data helpers
# ---------------------------------------------------------------------------

_FAKE_USERS = [f"user_{i:03d}" for i in range(1, 31)]
_FAKE_IPS = [f"192.168.{r}.{c}" for r in range(1, 6) for c in range(1, 21)]
_ATTACKER_IPS = ["10.0.0.99", "172.16.0.200", "203.0.113.5"]
_EVENT_TYPES = [
    "login_success",
    "login_failure",
    "file_access",
    "network_scan",
    "privilege_escalation",
    "data_exfiltration",
    "port_scan",
    "ssh_brute_force",
]


def _random_features(event_type: str, anomalous: bool) -> dict:
    """Generate plausible numeric features for a synthetic event."""
    base = {
        "bytes_sent":       random.randint(100, 500),
        "bytes_received":   random.randint(100, 500),
        "duration_sec":     round(random.uniform(0.1, 5.0), 2),
        "num_connections":  random.randint(1, 10),
        "failed_logins":    0,
        "port":             random.choice([22, 80, 443, 3389, 8080]),
    }
    if anomalous:
        base["bytes_sent"]       = random.randint(50_000, 500_000)
        base["num_connections"]  = random.randint(50, 500)
        base["failed_logins"]    = random.randint(6, 30)
        base["duration_sec"]     = round(random.uniform(10, 120), 2)
    return base


def _synthetic_event(anomaly_prob: float = 0.08) -> dict:
    """Create one synthetic event dict."""
    anomalous = random.random() < anomaly_prob
    src_ip = random.choice(_ATTACKER_IPS if anomalous else _FAKE_IPS)
    dst_ip = random.choice(_FAKE_IPS)
    user   = random.choice(_FAKE_USERS)
    etype  = random.choice(_EVENT_TYPES)
    features = _random_features(etype, anomalous)
    return make_event(src_ip, dst_ip, user, etype, features)


# ---------------------------------------------------------------------------
# CSV loading & column normalisation
# ---------------------------------------------------------------------------

_COLUMN_MAP = {
    # common Kaggle column names → internal names
    "src_ip":         "source_ip",
    "source_ip":      "source_ip",
    "dst_ip":         "dest_ip",
    "destination_ip": "dest_ip",
    "username":       "user",
    "user":           "user",
    "action":         "event_type",
    "event_type":     "event_type",
    "timestamp":      "timestamp",
}

_NUMERIC_COLS = [
    "bytes_sent", "bytes_received", "duration_sec",
    "num_connections", "failed_logins", "port",
]


def _load_csv() -> pd.DataFrame:
    """Load and lightly normalise the Kaggle CSV."""
    df = pd.read_csv(config.DATASET_PATH)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    df.rename(columns=_COLUMN_MAP, inplace=True)

    # Ensure required columns exist with sensible defaults
    for col in ["source_ip", "dest_ip", "user", "event_type"]:
        if col not in df.columns:
            df[col] = "unknown"
    if "timestamp" not in df.columns:
        df["timestamp"] = utc_now_str()

    # Ensure numeric feature columns exist
    for col in _NUMERIC_COLS:
        if col not in df.columns:
            df[col] = 0

    logger.info("Loaded dataset: %d rows, %d columns", len(df), len(df.columns))
    return df


def _row_to_event(row: pd.Series) -> dict:
    """Convert a CSV row to the internal event dict format."""
    features = {col: row.get(col, 0) for col in _NUMERIC_COLS}
    return make_event(
        source_ip=str(row.get("source_ip", "0.0.0.0")),
        dest_ip=str(row.get("dest_ip", "0.0.0.0")),
        user=str(row.get("user", "unknown")),
        event_type=str(row.get("event_type", "unknown")),
        raw_features=features,
        timestamp=str(row.get("timestamp", utc_now_str())),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EventSimulator:
    """
    Yields batches of event dicts that simulate a live security log stream.

    Usage
    -----
    sim = EventSimulator()
    for batch in sim.stream(max_batches=10):
        orchestrator.process(batch)
    """

    def __init__(self):
        self._csv_df: pd.DataFrame = None
        self._csv_index: int = 0
        self._use_csv: bool = os.path.exists(config.DATASET_PATH)

        if self._use_csv:
            try:
                self._csv_df = _load_csv()
                logger.info("Simulator: CSV mode active")
            except Exception as exc:
                logger.warning("CSV load failed (%s); falling back to synthetic.", exc)
                self._use_csv = False
        else:
            logger.info(
                "Simulator: Synthetic mode active (CSV not found at %s)",
                config.DATASET_PATH,
            )

    # ------------------------------------------------------------------
    def _next_batch_csv(self, batch_size: int) -> List[dict]:
        events = []
        for _ in range(batch_size):
            if self._csv_index >= len(self._csv_df):
                self._csv_index = 0  # loop back
            row = self._csv_df.iloc[self._csv_index]
            self._csv_index += 1
            events.append(_row_to_event(row))
        return events

    def _next_batch_synthetic(self, batch_size: int) -> List[dict]:
        return [_synthetic_event() for _ in range(batch_size)]

    # ------------------------------------------------------------------
    def next_batch(self, batch_size: int = None) -> List[dict]:
        """Return a single batch of events (does NOT sleep)."""
        size = batch_size or config.SIMULATION_BATCH_SIZE
        if self._use_csv:
            return self._next_batch_csv(size)
        return self._next_batch_synthetic(size)

    # ------------------------------------------------------------------
    def stream(
        self,
        max_batches: int = None,
        batch_size: int = None,
        sleep: bool = True,
    ) -> Generator[List[dict], None, None]:
        """
        Generator: yields one batch per iteration.

        Parameters
        ----------
        max_batches : stop after this many batches (None = infinite)
        batch_size  : events per batch
        sleep       : if True, waits config.SIMULATION_INTERVAL_SEC between batches
        """
        count = 0
        while True:
            yield self.next_batch(batch_size)
            count += 1
            if sleep:
                time.sleep(config.SIMULATION_INTERVAL_SEC)
            if max_batches is not None and count >= max_batches:
                break

    # ------------------------------------------------------------------
    @property
    def feature_columns(self) -> List[str]:
        """Numeric feature columns available for model training."""
        if self._use_csv and self._csv_df is not None:
            return [c for c in _NUMERIC_COLS if c in self._csv_df.columns]
        return _NUMERIC_COLS
