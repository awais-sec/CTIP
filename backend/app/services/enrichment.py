"""
Severity scoring engine.

Pure functions, no I/O — deliberately kept dependency-free so the scoring
logic can be unit tested in isolation (see backend/tests/test_enrichment.py)
and reasoned about independently of any particular feed's data shape.

Score is 0-100, derived from four weighted signals:
  1. Threat-type base severity (how dangerous this class of threat generally is)
  2. Source confidence (how sure the reporting feed is)
  3. Recency (fresher sightings are more actionable)
  4. Report volume (independently corroborated indicators are more trustworthy)
"""
from __future__ import annotations

from dataclasses import dataclass

# Base severity per threat type, on a 0-100 scale. Anything not listed here
# falls back to BASE_DEFAULT.
BASE_SEVERITY: dict[str, int] = {
    "ransomware": 96,
    "exploit": 90,
    "rootkit": 88,
    "c2": 86,
    "backdoor": 84,
    "botnet": 80,
    "infostealer": 78,
    "trojan": 75,
    "spyware": 72,
    "worm": 70,
    "webshell": 74,
    "ddos": 65,
    "brute_force": 62,
    "cryptomining": 55,
    "phishing": 60,
    "malware": 58,
    "scanning": 35,
    "suspicious": 40,
}
BASE_DEFAULT = 50

SEVERITY_LABELS = (
    (85, "critical"),
    (65, "high"),
    (40, "medium"),
    (0, "low"),
)

# Relative weighting of the four signals; must sum to 1.0
W_BASE = 0.45
W_CONFIDENCE = 0.25
W_RECENCY = 0.20
W_VOLUME = 0.10

RECENCY_HALF_LIFE_HOURS = 48.0  # recency signal decays to ~0 by ~4x this window


@dataclass(frozen=True)
class SeverityResult:
    score: int
    label: str


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def label_for_score(score: float) -> str:
    for threshold, label in SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "low"


def compute_severity(
    threat_type: str | None,
    confidence: float = 50,
    hours_since_seen: float = 0,
    times_reported: int = 1,
) -> SeverityResult:
    """
    Compute a 0-100 severity score and a human label for a threat event.

    - threat_type: e.g. "ransomware", "phishing", "malware" (case-insensitive)
    - confidence: 0-100, as supplied (or estimated) by the source feed
    - hours_since_seen: how many hours old the sighting is
    - times_reported: how many independent times this IOC has been reported
    """
    key = (threat_type or "").strip().lower().replace(" ", "_")
    base = BASE_SEVERITY.get(key, BASE_DEFAULT)

    confidence = _clamp(confidence)
    hours_since_seen = max(0.0, hours_since_seen)
    times_reported = max(1, int(times_reported))

    # Exponential decay: 100 at t=0, ~50 at t=half-life, asymptotic to 0
    recency_signal = 100.0 * (0.5 ** (hours_since_seen / RECENCY_HALF_LIFE_HOURS))

    # Diminishing returns on corroboration volume, caps out around 10 reports
    volume_signal = _clamp(100.0 * (1 - (0.75 ** (times_reported - 1))))

    score = (
        W_BASE * base
        + W_CONFIDENCE * confidence
        + W_RECENCY * recency_signal
        + W_VOLUME * volume_signal
    )
    score = round(_clamp(score))

    return SeverityResult(score=score, label=label_for_score(score))


def normalize_threat_type(raw: str | None) -> str:
    """Best-effort normalization of a free-text/feed-specific threat label
    into one of the canonical keys used by BASE_SEVERITY, so downstream
    scoring and MITRE mapping stay consistent."""
    if not raw:
        return "suspicious"
    text = raw.strip().lower()

    aliases = {
        "payload_delivery": "malware",
        "malware_download": "malware",
        "url": "malware",
        "botnet_cc": "c2",
        "c&c": "c2",
        "cnc": "c2",
        "command_and_control": "c2",
        "info_stealer": "infostealer",
        "stealer": "infostealer",
        "crypto_miner": "cryptomining",
        "coinminer": "cryptomining",
        "web_shell": "webshell",
        "bruteforce": "brute_force",
        "port_scan": "scanning",
        "recon": "scanning",
    }
    text = aliases.get(text, text)

    if text in BASE_SEVERITY:
        return text

    # substring fallback (e.g. "ransomware.locky" -> "ransomware")
    for key in BASE_SEVERITY:
        if key in text:
            return key
    return "suspicious"
