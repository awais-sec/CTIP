import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.enrichment import compute_severity, label_for_score, normalize_threat_type


def test_ransomware_fresh_high_confidence_is_critical():
    result = compute_severity("ransomware", confidence=95, hours_since_seen=0, times_reported=5)
    assert result.label == "critical"
    assert result.score >= 85


def test_scanning_old_low_confidence_is_low():
    result = compute_severity("scanning", confidence=10, hours_since_seen=500, times_reported=1)
    assert result.label == "low"
    assert result.score < 40


def test_score_bounded_0_to_100():
    for threat_type in ["ransomware", "phishing", "unknown_type", None]:
        for conf in [-50, 0, 50, 100, 500]:
            for hours in [0, 24, 1000]:
                for reports in [0, 1, 100]:
                    result = compute_severity(threat_type, conf, hours, reports)
                    assert 0 <= result.score <= 100


def test_more_reports_never_decreases_score():
    low = compute_severity("malware", confidence=50, hours_since_seen=10, times_reported=1)
    high = compute_severity("malware", confidence=50, hours_since_seen=10, times_reported=10)
    assert high.score >= low.score


def test_recency_decay_monotonic():
    fresh = compute_severity("trojan", confidence=60, hours_since_seen=0)
    stale = compute_severity("trojan", confidence=60, hours_since_seen=200)
    assert fresh.score >= stale.score


def test_label_thresholds():
    assert label_for_score(90) == "critical"
    assert label_for_score(70) == "high"
    assert label_for_score(45) == "medium"
    assert label_for_score(10) == "low"
    assert label_for_score(85) == "critical"
    assert label_for_score(64.9) == "medium"


def test_normalize_threat_type_aliases_and_fallback():
    assert normalize_threat_type("Botnet_CC") == "c2"
    assert normalize_threat_type("ransomware.locky") == "ransomware"
    assert normalize_threat_type(None) == "suspicious"
    assert normalize_threat_type("totally_unknown_xyz") == "suspicious"
    assert normalize_threat_type("PHISHING") == "phishing"
