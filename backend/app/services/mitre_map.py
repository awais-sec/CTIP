"""
Lightweight, dependency-free heuristic mapping from threat-type/keyword
labels (as reported by OSINT feeds) to MITRE ATT&CK (Enterprise) techniques.

This is intentionally a curated lookup table rather than an ML classifier:
it's transparent, fast, testable with no network access, and good enough to
give every ingested IOC useful ATT&CK context for the dashboard's heatmap.
"""
from __future__ import annotations

# Each entry: keyword -> list of (technique_id, technique_name, tactic)
TECHNIQUE_MAP: dict[str, list[tuple[str, str, str]]] = {
    "phishing": [("T1566", "Phishing", "Initial Access")],
    "spearphishing": [("T1566.001", "Spearphishing Attachment", "Initial Access")],
    "malware": [("T1105", "Ingress Tool Transfer", "Command and Control")],
    "trojan": [("T1204", "User Execution", "Execution")],
    "ransomware": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1490", "Inhibit System Recovery", "Impact"),
    ],
    "botnet": [("T1584", "Compromise Infrastructure", "Resource Development")],
    "c2": [("T1071", "Application Layer Protocol", "Command and Control")],
    "command and control": [("T1071", "Application Layer Protocol", "Command and Control")],
    "exploit": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "backdoor": [("T1505", "Server Software Component", "Persistence")],
    "spyware": [("T1056", "Input Capture", "Collection")],
    "infostealer": [("T1555", "Credentials from Password Stores", "Credential Access")],
    "stealer": [("T1555", "Credentials from Password Stores", "Credential Access")],
    "worm": [("T1210", "Exploitation of Remote Services", "Lateral Movement")],
    "ddos": [("T1498", "Network Denial of Service", "Impact")],
    "cryptomining": [("T1496", "Resource Hijacking", "Impact")],
    "cryptominer": [("T1496", "Resource Hijacking", "Impact")],
    "rootkit": [("T1014", "Rootkit", "Defense Evasion")],
    "downloader": [("T1105", "Ingress Tool Transfer", "Command and Control")],
    "loader": [("T1105", "Ingress Tool Transfer", "Command and Control")],
    "webshell": [("T1505.003", "Web Shell", "Persistence")],
    "brute": [("T1110", "Brute Force", "Credential Access")],
    "scanning": [("T1595", "Active Scanning", "Reconnaissance")],
    "suspicious": [("T1588", "Obtain Capabilities", "Resource Development")],
}

DEFAULT_TECHNIQUE = ("T1588", "Obtain Capabilities", "Resource Development")


def get_techniques(threat_type: str | None, tags: list[str] | None = None) -> list[dict]:
    """
    Return a de-duplicated list of MITRE ATT&CK technique dicts relevant to
    the given threat type and any extra tags/keywords from the source feed.
    """
    haystack: list[str] = []
    if threat_type:
        haystack.append(threat_type.lower())
    for tag in tags or []:
        if tag:
            haystack.append(str(tag).lower())

    matched: dict[str, dict] = {}
    for phrase in haystack:
        for keyword, techniques in TECHNIQUE_MAP.items():
            if keyword in phrase:
                for tid, name, tactic in techniques:
                    matched[tid] = {"id": tid, "name": name, "tactic": tactic}

    if not matched:
        tid, name, tactic = DEFAULT_TECHNIQUE
        matched[tid] = {"id": tid, "name": name, "tactic": tactic}

    return sorted(matched.values(), key=lambda t: t["id"])


def all_known_techniques() -> list[dict]:
    """Full de-duplicated technique catalog, used to seed the ATT&CK matrix view."""
    seen: dict[str, dict] = {}
    for techniques in TECHNIQUE_MAP.values():
        for tid, name, tactic in techniques:
            seen[tid] = {"id": tid, "name": name, "tactic": tactic}
    tid, name, tactic = DEFAULT_TECHNIQUE
    seen[tid] = {"id": tid, "name": name, "tactic": tactic}
    return sorted(seen.values(), key=lambda t: t["id"])
