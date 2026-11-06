"""
Synthetic threat data generator.

CTIP is built to run against real, live threat intel feeds. But a portfolio
project should also work perfectly the moment someone clones the repo,
before they've configured anything or if their network blocks outbound
abuse.ch/NVD calls. This module generates clearly-labeled, plausible-looking
demo data (source_feed="demo-simulator", is_synthetic=True) so the dashboard
is always populated and demonstrable.

Every synthetic record is flagged as such at the API and UI level — this is
never presented as real threat intelligence.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from app.services.enrichment import normalize_threat_type
from app.services.feeds.base import RawIOC

# A representative spread of world cities (lat/lon are approximate city
# centers) used to keep the demo map visually realistic and globally spread.
_CITIES: list[tuple[str, str, float, float]] = [
    ("United States", "US", 38.9, -77.0),
    ("United States", "US", 37.77, -122.42),
    ("Russia", "RU", 55.75, 37.62),
    ("China", "CN", 39.9, 116.4),
    ("China", "CN", 31.23, 121.47),
    ("Germany", "DE", 52.52, 13.4),
    ("Netherlands", "NL", 52.37, 4.9),
    ("Brazil", "BR", -23.55, -46.63),
    ("India", "IN", 28.61, 77.21),
    ("Vietnam", "VN", 21.03, 105.85),
    ("Ukraine", "UA", 50.45, 30.52),
    ("Iran", "IR", 35.69, 51.39),
    ("North Korea", "KP", 39.03, 125.75),
    ("United Kingdom", "GB", 51.51, -0.13),
    ("France", "FR", 48.85, 2.35),
    ("South Korea", "KR", 37.57, 126.98),
    ("Nigeria", "NG", 6.52, 3.38),
    ("Indonesia", "ID", -6.2, 106.85),
    ("Romania", "RO", 44.43, 26.1),
    ("Poland", "PL", 52.23, 21.01),
    ("Turkey", "TR", 41.0, 28.98),
    ("Singapore", "SG", 1.35, 103.82),
    ("Canada", "CA", 45.42, -75.7),
    ("Japan", "JP", 35.68, 139.69),
    ("South Africa", "ZA", -26.2, 28.05),
]

_MALWARE_FAMILIES = [
    "Emotet", "TrickBot", "Qakbot", "AgentTesla", "Redline Stealer", "Cobalt Strike",
    "AsyncRAT", "Lokibot", "IcedID", "Formbook", "Raccoon Stealer", "Mirai",
    "Gh0stRAT", "NetWire", "Remcos", "SmokeLoader", "Dridex", "BlackCat/ALPHV",
    "LockBit", "Conti", "Ursnif", "XWorm", "Vidar Stealer",
]

_THREAT_TYPES = [
    "ransomware", "trojan", "botnet", "c2", "phishing", "infostealer",
    "backdoor", "cryptomining", "worm", "webshell", "ddos", "rootkit",
]

_DOMAIN_WORDS = [
    "secure", "update", "login", "verify", "cloud", "service", "account",
    "billing", "portal", "mail", "auth", "cdn-edge", "app", "gateway", "vpn",
]
_TLDS = [".xyz", ".top", ".info", ".online", ".ru", ".cn", ".click", ".site", ".biz", ".net"]

_CVE_PRODUCTS = [
    ("Microsoft", "Windows"), ("Apache", "HTTP Server"), ("Fortinet", "FortiOS"),
    ("Cisco", "IOS XE"), ("Ivanti", "Connect Secure"), ("Oracle", "WebLogic Server"),
    ("Atlassian", "Confluence"), ("VMware", "vCenter Server"), ("Adobe", "Acrobat Reader"),
    ("PHP", "PHP"), ("WordPress", "Core"), ("GitLab", "GitLab CE/EE"),
]


def _random_ip() -> str:
    # Avoid 0.x, 10.x, 127.x, 192.168.x etc. to look like plausible public IPs.
    first = random.choice([i for i in range(20, 224) if i not in (10, 127, 172, 192)])
    return f"{first}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _random_domain() -> str:
    word = random.choice(_DOMAIN_WORDS)
    suffix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=5))
    return f"{word}-{suffix}{random.choice(_TLDS)}"


def _random_hash(seed: str) -> str:
    return hashlib.sha256(f"{seed}{random.random()}".encode()).hexdigest()


def generate_synthetic_events(n: int = 40) -> list[RawIOC]:
    events: list[RawIOC] = []
    now = datetime.now(timezone.utc)

    for _ in range(n):
        threat_type = random.choice(_THREAT_TYPES)
        ioc_type = random.choices(["ip", "domain", "hash", "url"], weights=[35, 30, 20, 15])[0]

        if ioc_type == "ip":
            value = _random_ip()
        elif ioc_type == "domain":
            value = _random_domain()
        elif ioc_type == "url":
            value = f"http://{_random_domain()}/{random.choice(['update.exe','invoice.pdf.exe','login','panel/gate.php'])}"
        else:
            value = _random_hash(str(random.random()))

        family = random.choice(_MALWARE_FAMILIES)
        hours_ago = random.choices(
            [round(random.uniform(0, 3), 2), random.uniform(3, 24), random.uniform(24, 96)],
            weights=[45, 35, 20],
        )[0]
        first_seen = (now - timedelta(hours=hours_ago)).isoformat()

        events.append(
            RawIOC(
                ioc_value=value,
                ioc_type=ioc_type,
                threat_type=normalize_threat_type(threat_type),
                source_feed="demo-simulator",
                confidence=random.randint(45, 95),
                malware_family=family,
                first_seen=first_seen,
                times_reported=random.randint(1, 8),
                tags=[family, threat_type, "demo"],
                reference_url=None,
            )
        )
    return events


def generate_synthetic_geo() -> dict:
    """Returns a random plausible location, used when demo IOCs need coords
    directly (bypassing the real geoip service, since demo IPs aren't real)."""
    country, code, lat, lon = random.choice(_CITIES)
    # Jitter slightly so markers don't all stack on exact city centers
    return {
        "country": country,
        "country_code": code,
        "lat": lat + random.uniform(-1.5, 1.5),
        "lon": lon + random.uniform(-1.5, 1.5),
        "asn": f"AS{random.randint(1000, 65000)} DEMO-NET",
    }


def generate_synthetic_cves(n: int = 15) -> list[dict]:
    now = datetime.now(timezone.utc)
    results = []
    for _ in range(n):
        vendor, product = random.choice(_CVE_PRODUCTS)
        year = random.choice([2024, 2025, 2026])
        cve_id = f"CVE-{year}-{random.randint(10000, 49999)}"
        score = round(random.uniform(6.0, 9.9), 1)
        is_kev = random.random() < 0.3
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium"
        days_ago = random.uniform(0, 30)
        results.append(
            {
                "cve_id": cve_id,
                "description": (
                    f"A vulnerability in {vendor} {product} allows a remote "
                    f"attacker to {random.choice(['execute arbitrary code', 'bypass authentication', 'escalate privileges', 'cause a denial of service', 'read arbitrary files'])} "
                    f"via a crafted request. (Simulated demo record.)"
                ),
                "cvss_score": score,
                "severity": severity,
                "vendor_project": vendor,
                "product": product,
                "is_kev": is_kev,
                "kev_due_date": (now + timedelta(days=random.randint(7, 21))).strftime("%Y-%m-%d")
                if is_kev
                else None,
                "ransomware_use": is_kev and random.random() < 0.4,
                "published_date": (now - timedelta(days=days_ago)).isoformat(),
                "is_synthetic": True,
            }
        )
    return results
