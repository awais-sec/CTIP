import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.mitre_map import all_known_techniques, get_techniques


def test_ransomware_maps_to_impact_techniques():
    techniques = get_techniques("ransomware")
    ids = {t["id"] for t in techniques}
    assert "T1486" in ids


def test_unknown_type_falls_back_to_default():
    techniques = get_techniques("something_never_seen_before")
    assert len(techniques) == 1
    assert techniques[0]["id"] == "T1588"


def test_tags_contribute_additional_techniques():
    techniques = get_techniques("malware", tags=["phishing", "c2"])
    ids = {t["id"] for t in techniques}
    assert "T1566" in ids
    assert "T1071" in ids
    assert "T1105" in ids


def test_no_duplicate_technique_ids():
    techniques = get_techniques("phishing", tags=["phishing", "spearphishing"])
    ids = [t["id"] for t in techniques]
    assert len(ids) == len(set(ids))


def test_all_known_techniques_nonempty_and_unique():
    techniques = all_known_techniques()
    ids = [t["id"] for t in techniques]
    assert len(techniques) > 10
    assert len(ids) == len(set(ids))
