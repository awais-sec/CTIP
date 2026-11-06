import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.campaign_correlation import correlate_events


def _event(id, malware_family=None, asn=None, threat_type="malware", severity_score=50,
           severity_label="medium", country="US", first_seen="2026-01-01T00:00:00", last_seen=None):
    return {
        "id": id,
        "ioc_value": f"ioc-{id}",
        "ioc_type": "ip",
        "threat_type": threat_type,
        "malware_family": malware_family,
        "asn": asn,
        "severity_score": severity_score,
        "severity_label": severity_label,
        "country": country,
        "first_seen": first_seen,
        "last_seen": last_seen or first_seen,
    }


def test_shared_family_forms_one_campaign():
    events = [
        _event(1, malware_family="LockBit"),
        _event(2, malware_family="LockBit"),
        _event(3, malware_family="LockBit"),
    ]
    result = correlate_events(events)
    assert len(result["campaigns"]) == 1
    campaign = result["campaigns"][0]
    assert campaign["kind"] == "malware_family"
    assert campaign["member_count"] == 3
    assert result["ungrouped_count"] == 0


def test_unknown_family_markers_do_not_cluster():
    events = [_event(1, malware_family="Unknown"), _event(2, malware_family=None), _event(3, malware_family="")]
    result = correlate_events(events)
    assert result["campaigns"] == []
    assert result["ungrouped_count"] == 3


def test_shared_asn_fallback_when_no_family():
    events = [
        _event(1, asn="AS123 EVILNET"),
        _event(2, asn="AS123 EVILNET"),
    ]
    result = correlate_events(events)
    assert len(result["campaigns"]) == 1
    assert result["campaigns"][0]["kind"] == "shared_infrastructure"


def test_family_signal_takes_priority_over_asn():
    events = [
        _event(1, malware_family="LockBit", asn="AS999 SHARED"),
        _event(2, malware_family="LockBit", asn="AS999 SHARED"),
    ]
    result = correlate_events(events)
    assert len(result["campaigns"]) == 1
    assert result["campaigns"][0]["kind"] == "malware_family"


def test_below_min_cluster_size_is_ungrouped():
    events = [_event(1, malware_family="RareFamily")]
    result = correlate_events(events, min_cluster_size=2)
    assert result["campaigns"] == []
    assert result["ungrouped_count"] == 1


def test_graph_has_star_topology_edges_linear_in_size():
    events = [_event(i, malware_family="Emotet") for i in range(1, 6)]
    result = correlate_events(events)
    assert len(result["graph"]["nodes"]) == 5
    assert len(result["graph"]["edges"]) == 4  # star: hub -> each other member


def test_no_duplicate_nodes_across_clusters():
    events = [
        _event(1, malware_family="Emotet"),
        _event(2, malware_family="Emotet"),
        _event(3, malware_family="TrickBot"),
        _event(4, malware_family="TrickBot"),
    ]
    result = correlate_events(events)
    node_ids = [n["id"] for n in result["graph"]["nodes"]]
    assert len(node_ids) == len(set(node_ids)) == 4


def test_campaign_aggregates_countries_and_max_severity():
    events = [
        _event(1, malware_family="Emotet", country="US", severity_score=60),
        _event(2, malware_family="Emotet", country="DE", severity_score=90),
    ]
    result = correlate_events(events)
    campaign = result["campaigns"][0]
    assert campaign["countries"] == ["DE", "US"]
    assert campaign["max_severity"] == 90


def test_campaigns_sorted_by_severity_then_size():
    events = [
        _event(1, malware_family="Low", severity_score=40),
        _event(2, malware_family="Low", severity_score=40),
        _event(3, malware_family="High", severity_score=95),
        _event(4, malware_family="High", severity_score=95),
    ]
    result = correlate_events(events)
    assert result["campaigns"][0]["label"] == "High"
