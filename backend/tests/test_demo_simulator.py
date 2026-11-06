import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.feeds.demo_simulator import (
    generate_synthetic_cves,
    generate_synthetic_events,
    generate_synthetic_geo,
)


def test_generate_synthetic_events_count_and_shape():
    events = generate_synthetic_events(n=25)
    assert len(events) == 25
    for e in events:
        assert e.ioc_value
        assert e.ioc_type in {"ip", "domain", "hash", "url"}
        assert e.source_feed == "demo-simulator"
        assert 0 <= e.confidence <= 100
        assert e.times_reported >= 1


def test_generate_synthetic_events_unique_values_mostly():
    events = generate_synthetic_events(n=100)
    values = [e.ioc_value for e in events]
    # Not a hard uniqueness guarantee (randomness), but should be highly unique
    assert len(set(values)) > 90


def test_generate_synthetic_geo_has_valid_coords():
    for _ in range(20):
        geo = generate_synthetic_geo()
        assert -90 <= geo["lat"] <= 90
        assert -180 <= geo["lon"] <= 180
        assert geo["country_code"]


def test_generate_synthetic_cves_shape():
    cves = generate_synthetic_cves(n=10)
    assert len(cves) == 10
    for c in cves:
        assert c["cve_id"].startswith("CVE-")
        assert 0 <= c["cvss_score"] <= 10
        assert c["is_synthetic"] is True
