"""
AlienVault OTX (Open Threat Exchange) — optional feed. Requires a free API
key (set CTIP_OTX_API_KEY). Skipped automatically when no key is configured
so the platform still runs fully without it.

Docs: https://otx.alienvault.com/api
"""
from __future__ import annotations

from app.config import settings
from app.services.enrichment import normalize_threat_type
from app.services.feeds.base import RawIOC, http_get, logger

FEED_NAME = "otx"
PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

OTX_INDICATOR_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


def fetch(limit: int = 100) -> list[RawIOC]:
    if not settings.OTX_API_KEY:
        logger.info("otx: no API key configured, skipping")
        return []

    try:
        resp = http_get(
            PULSES_URL,
            params={"limit": 20},
            headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("otx fetch failed: %s", exc)
        return []

    results: list[RawIOC] = []
    for pulse in (payload or {}).get("results", []):
        tags = pulse.get("tags") or []
        pulse_name = pulse.get("name", "")
        for indicator in pulse.get("indicators", []):
            if len(results) >= limit:
                break
            try:
                itype = OTX_INDICATOR_TYPE_MAP.get(indicator.get("type"))
                value = indicator.get("indicator")
                if not itype or not value:
                    continue
                results.append(
                    RawIOC(
                        ioc_value=value,
                        ioc_type=itype,
                        threat_type=normalize_threat_type(pulse_name or "malware"),
                        source_feed=FEED_NAME,
                        confidence=65,
                        first_seen=indicator.get("created"),
                        tags=list(tags),
                        reference_url=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("otx: skipping malformed indicator: %s", exc)
                continue

    logger.info("otx: parsed %d IOCs", len(results))
    return results
