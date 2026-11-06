"""
ThreatFox (abuse.ch) — free API sharing recent IOCs (IPs, domains, URLs,
hashes) tied to specific malware families, each with a feed-reported
confidence level.

As of abuse.ch's 2025 policy change, this API requires a free Auth-Key
(register at https://auth.abuse.ch/, no cost). Set CTIP_ABUSECH_AUTH_KEY.
Without one, this connector is skipped gracefully — the platform still
runs fine on URLhaus + CISA KEV + NVD + demo-mode fill.

Docs: https://threatfox.abuse.ch/api/
Endpoint: POST https://threatfox-api.abuse.ch/api/v1/  body: {"query": "get_iocs", "days": N}
Header: Auth-Key: <your key>
"""
from __future__ import annotations

from app.config import settings
from app.services.enrichment import normalize_threat_type
from app.services.feeds.base import RawIOC, http_post, logger

FEED_NAME = "threatfox"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"

IOC_TYPE_MAP = {
    "ip:port": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",
}


def fetch(days: int = 1, limit: int = 150) -> list[RawIOC]:
    if not settings.ABUSECH_AUTH_KEY:
        logger.info("threatfox: no Auth-Key configured (get one free at https://auth.abuse.ch/), skipping")
        return []

    try:
        resp = http_post(
            API_URL,
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": settings.ABUSECH_AUTH_KEY},
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("threatfox fetch failed: %s", exc)
        return []

    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        logger.warning("threatfox: unexpected response status: %s", (payload or {}).get("query_status"))
        return []

    data = payload.get("data") or []
    results: list[RawIOC] = []

    for entry in data[:limit]:
        try:
            ioc_value = entry.get("ioc")
            if not ioc_value:
                continue
            raw_type = (entry.get("ioc_type") or "").lower()
            ioc_type = IOC_TYPE_MAP.get(raw_type, "domain")

            threat_type_raw = entry.get("threat_type") or entry.get("threat_type_desc") or "malware"
            tags = entry.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            malware_family = entry.get("malware_printable") or entry.get("malware")

            port_tag = None
            if raw_type == "ip:port" and ":" in ioc_value:
                # ThreatFox reports "ip:port" C2 endpoints as one string, but
                # ioc_type is normalized to plain "ip" for scoring/mapping —
                # strip the port so downstream GeoIP lookups (which query the
                # bare IP) don't silently fail, and keep it as a tag instead
                # of dropping it outright.
                host_part, _, port_part = ioc_value.rpartition(":")
                if host_part:
                    ioc_value = host_part
                    port_tag = f"port:{port_part}"

            results.append(
                RawIOC(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    threat_type=normalize_threat_type(threat_type_raw),
                    source_feed=FEED_NAME,
                    confidence=int(entry.get("confidence_level") or 50),
                    malware_family=malware_family,
                    first_seen=entry.get("first_seen"),
                    tags=[str(t) for t in tags]
                    + ([malware_family] if malware_family else [])
                    + ([port_tag] if port_tag else []),
                    reference_url=entry.get("reference"),
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("threatfox: skipping malformed entry: %s", exc)
            continue

    logger.info("threatfox: parsed %d IOCs", len(results))
    return results
