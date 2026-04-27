"""
utils/helpers.py
================
Shared utilities: logging setup, timestamp helpers, dict normalisation,
and the byte-to-image converter extracted from the original notebook.
"""

import logging
import os
import sys
import time
import numpy as np
from datetime import datetime, timezone
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger.  First call also adds handlers; subsequent
    calls for the same *name* just return the existing logger.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Optional file handler
    if config.LOG_TO_FILE:
        os.makedirs(os.path.dirname(config.LOG_FILE_PATH), exist_ok=True)
        fh = logging.FileHandler(config.LOG_FILE_PATH)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def utc_now_str() -> str:
    """ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch_ms() -> int:
    """Current Unix time in milliseconds."""
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Event / dict helpers
# ---------------------------------------------------------------------------

def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a value to [lo, hi]."""
    return max(lo, min(hi, value))


def severity_label(score: float) -> str:
    """
    Map a normalised anomaly score (0-1) to a severity string.
    Thresholds come from config so they stay consistent across agents.
    """
    if score >= config.CRITICAL_SEVERITY_THRESHOLD:
        return "critical"
    if score >= config.HIGH_SEVERITY_THRESHOLD:
        return "high"
    if score >= config.ANOMALY_SCORE_THRESHOLD:
        return "medium"
    return "low"


def make_event(
    source_ip: str,
    dest_ip: str,
    user: str,
    event_type: str,
    raw_features: dict,
    timestamp: Optional[str] = None,
) -> dict:
    """
    Factory for a standardised event dict that flows through the pipeline.
    """
    return {
        "timestamp": timestamp or utc_now_str(),
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "user": user,
        "event_type": event_type,
        "raw_features": raw_features,
        # Fields filled in by downstream agents:
        "anomaly_score": None,
        "is_anomaly": None,
        "severity": None,
        "decision": None,
        "malware_label": None,
        "response_action": None,
    }


# ---------------------------------------------------------------------------
# Malware byte-to-image converter  (core logic from the notebook)
# ---------------------------------------------------------------------------

def parse_hexdump(filepath: str) -> np.ndarray:
    """
    Parse a Kaggle-style .bytes hexdump file into a flat uint8 numpy array.

    Each line has the format:
        <offset>  <byte0> <byte1> ... <byteN>
    where bytes may be '??' for unknown / unreadable bytes (replaced with 0).

    This is the exact algorithm from the original notebook, cleaned up and
    made importable.
    """
    byte_list = []
    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            # Skip the first token (offset); rest are hex bytes
            hex_bytes = parts[1:]
            for b in hex_bytes:
                byte_list.append(0x00 if b == "??" else int(b, 16))
    return np.array(byte_list, dtype=np.uint8)


def bytes_to_image(byte_array: np.ndarray, size: tuple = None) -> np.ndarray:
    """
    Reshape a flat byte array into an (H, W, 3) RGB image numpy array.

    Steps (matching notebook logic):
      1. Pad or truncate to exactly size[0] * size[1] * 3 bytes.
      2. Reshape to (H, W, 3).

    Parameters
    ----------
    byte_array : flat uint8 array
    size       : (width, height) tuple; defaults to config.MALWARE_IMAGE_SIZE

    Returns
    -------
    np.ndarray of shape (H, W, 3), dtype uint8
    """
    if size is None:
        size = config.MALWARE_IMAGE_SIZE
    w, h = size
    required = w * h * config.MALWARE_CHANNELS
    n = len(byte_array)

    if n < required:
        byte_array = np.pad(byte_array, (0, required - n), mode="constant")
    else:
        byte_array = byte_array[:required]

    return byte_array.reshape((h, w, config.MALWARE_CHANNELS))


def simulate_malware_image(seed: Optional[int] = None) -> np.ndarray:
    """
    Generate a random byte-image for demo purposes when no real .bytes
    files are available.
    """
    rng = np.random.default_rng(seed)
    w, h = config.MALWARE_IMAGE_SIZE
    return rng.integers(0, 256, size=(h, w, config.MALWARE_CHANNELS), dtype=np.uint8)
