"""
config.py
=========
Central configuration for the entire seminar_project.
Every module imports from here instead of hardcoding values.
"""

import os

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Dataset CSV (Kaggle: synthetic-cybersecurity-logs-for-anomaly-detection)
DATASET_PATH = os.path.join(DATA_DIR, "cybersecurity_logs.csv")

# Malware byte samples directory (optional; used by MalwareAgent)
MALWARE_BYTES_DIR = os.path.join(DATA_DIR, "malware_bytes")

# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
SIMULATION_BATCH_SIZE = 20          # events emitted per simulation tick
SIMULATION_INTERVAL_SEC = 2.0       # seconds between ticks (UI auto-refresh)
RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------------
IF_N_ESTIMATORS = 100
IF_CONTAMINATION = 0.05             # expected fraction of anomalies
IF_MAX_SAMPLES = "auto"
IF_RANDOM_STATE = RANDOM_SEED

# ---------------------------------------------------------------------------
# Z-Score detector
# ---------------------------------------------------------------------------
ZSCORE_THRESHOLD = 3.0              # |z| > this → anomaly
ZSCORE_ROLLING_WINDOW = 50          # rows used for rolling mean/std

# ---------------------------------------------------------------------------
# UBA (User Behaviour Analytics)
# ---------------------------------------------------------------------------
UBA_MAX_FAILED_LOGINS = 5           # per user, before flagging
UBA_MAX_DISTINCT_IPS = 3            # unique source IPs per user, before flagging
UBA_LOOKBACK_ROWS = 200             # rows considered as recent history

# ---------------------------------------------------------------------------
# Decision thresholds
# ---------------------------------------------------------------------------
ANOMALY_SCORE_THRESHOLD = 0.5       # combined score → trigger decision
HIGH_SEVERITY_THRESHOLD = 0.75      # escalate to malware analysis
CRITICAL_SEVERITY_THRESHOLD = 0.9   # trigger hard block

# ---------------------------------------------------------------------------
# Malware CV model
# ---------------------------------------------------------------------------
MALWARE_IMAGE_SIZE = (64, 64)       # (width, height) for byte→image resize
MALWARE_CHANNELS = 3                # RGB
# Simulated class labels (no real model weights needed for the demo)
MALWARE_CLASSES = [
    "benign",
    "trojan",
    "ransomware",
    "worm",
    "adware",
    "spyware",
]
MALWARE_CONFIDENCE_THRESHOLD = 0.55 # below this → "uncertain"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_TO_FILE = True
LOG_FILE_PATH = os.path.join(LOGS_DIR, "system.log")
LOG_LEVEL = "INFO"                  # DEBUG | INFO | WARNING | ERROR

# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------
RESPONSE_ACTIONS = {
    "low":      "log_and_monitor",
    "medium":   "alert_and_throttle",
    "high":     "block_ip",
    "critical": "isolate_host",
}
