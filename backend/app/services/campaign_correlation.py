"""
Campaign correlation engine.

Turns a flat list of IOCs into inferred "campaigns" — groups of indicators
that are probably part of the same attacker operation. Like the severity
scoring and MITRE mapping engines, this is a transparent heuristic rather
than an ML model: fast, dependency-free, testable offline, and easy for a
reader to audit.

Two correlation signals, tried in order of confidence:
  1. Shared malware family — the strongest signal a feed can give us
     directly (e.g. every "LockBit" IOC is presumed related).
  2. Shared hosting infrastructure (ASN) — for IOCs with no usable family
     (common for raw URL/domain feeds), indicators hosted on the same
     network are still a meaningful (if weaker) correlation signal, since
     attackers frequently reuse infrastructure across campaigns.

A group smaller than `min_cluster_size` isn't a "campaign" — it's just one
indicator — and is left out of the result entirely.
"""
from __future__ import annotations

from collections import defaultdict

# Values that mean "no real family was reported" rather than a genuine
# shared identity — grouping on these would create one giant meaningless
# cluster instead of a real campaign.
_UNKNOWN_FAMILY_MARKERS = {"", "unknown", "unknown malware", "n/a", "none", "null"}


def _family_key(event: dict) -> str | None:
    family = (event.get("malware_family") or "").strip()
    if not family or family.lower() in _UNKNOWN_FAMILY_MARKERS:
        return None
    return f"family:{family.lower()}"


def _asn_key(event: dict) -> str | None:
    asn = (event.get("asn") or "").strip()
    if not asn:
        return None
    return f"asn:{asn.lower()}"


def _campaign_label(kind: str, key: str, members: list[dict]) -> str:
    if kind == "malware_family":
        return members[0].get("malware_family") or key.split(":", 1)[1].title()
    return f"Shared infra — {members[0].get('asn') or key.split(':', 1)[1]}"


def correlate_events(events: list[dict], min_cluster_size: int = 2) -> dict:
    """
    Groups threat-event dicts (as produced by ThreatEvent.to_dict()) into
    inferred campaigns and a small graph for visualization.

    Returns:
        {
          "campaigns": [{id, kind, label, member_count, countries,
                         threat_types, max_severity, first_seen, last_seen}, ...],
          "graph": {"nodes": [...], "edges": [...]},
          "ungrouped_count": int,
        }

    Edges are a star topology per cluster (hub = earliest-seen member) so
    edge count stays linear in event count rather than quadratic.
    """
    family_groups: dict[str, list[dict]] = defaultdict(list)
    remaining: list[dict] = []
    for event in events:
        key = _family_key(event)
        if key:
            family_groups[key].append(event)
        else:
            remaining.append(event)

    asn_groups: dict[str, list[dict]] = defaultdict(list)
    ungrouped: list[dict] = []
    for event in remaining:
        key = _asn_key(event)
        if key:
            asn_groups[key].append(event)
        else:
            ungrouped.append(event)

    clusters: list[tuple[str, str, list[dict]]] = []  # (key, kind, members)
    for key, members in family_groups.items():
        if len(members) >= min_cluster_size:
            clusters.append((key, "malware_family", members))
        else:
            ungrouped.extend(members)
    for key, members in asn_groups.items():
        if len(members) >= min_cluster_size:
            clusters.append((key, "shared_infrastructure", members))
        else:
            ungrouped.extend(members)

    campaigns: list[dict] = []
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_node_ids: set = set()

    for key, kind, members in clusters:
        members_sorted = sorted(members, key=lambda m: m.get("first_seen") or "")
        hub = members_sorted[0]

        countries = sorted({m["country"] for m in members if m.get("country")})
        threat_types = sorted({m["threat_type"] for m in members if m.get("threat_type")})
        max_severity = max((m.get("severity_score") or 0) for m in members)
        seen_dates = [m.get("first_seen") for m in members if m.get("first_seen")]
        last_dates = [m.get("last_seen") for m in members if m.get("last_seen")]

        campaigns.append(
            {
                "id": key,
                "kind": kind,
                "label": _campaign_label(kind, key, members),
                "member_count": len(members),
                "countries": countries,
                "threat_types": threat_types,
                "max_severity": max_severity,
                "first_seen": min(seen_dates) if seen_dates else None,
                "last_seen": max(last_dates) if last_dates else None,
            }
        )

        for member in members_sorted:
            if member["id"] in seen_node_ids:
                continue
            nodes.append(
                {
                    "id": member["id"],
                    "ioc_value": member.get("ioc_value"),
                    "ioc_type": member.get("ioc_type"),
                    "threat_type": member.get("threat_type"),
                    "severity_label": member.get("severity_label"),
                    "severity_score": member.get("severity_score"),
                    "country": member.get("country"),
                    "campaign_id": key,
                }
            )
            seen_node_ids.add(member["id"])

        for member in members_sorted[1:]:
            edges.append({"source": hub["id"], "target": member["id"]})

    campaigns.sort(key=lambda c: (c["max_severity"], c["member_count"]), reverse=True)

    return {
        "campaigns": campaigns,
        "graph": {"nodes": nodes, "edges": edges},
        "ungrouped_count": len(ungrouped),
    }
