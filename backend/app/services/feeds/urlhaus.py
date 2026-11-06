"""
URLhaus (abuse.ch) — free, no-auth-required feed of recently submitted
malicious URLs used for malware distribution.

Docs: https://urlhaus.abuse.ch/api/
Bulk JSON export (recent, last ~30 days, no auth): 
    https://urlhaus.abuse.ch/downloads/json_recent/

NOTE: abuse.ch periodically evolves its API surface. This connector parses
defensively (missing/renamed fields are skipped, not fatal) and the
aggregator falls back to demo data if this returns nothing, so an upstream
change degrades gracefully rather than breaking the platform.
"""
from __future__ import annotations

from app.services.enrichment import normalize_threat_type
from app.services.feeds.base import RawIOC, http_get, logger

FEED_NAME = "urlhaus"
RECENT_JSON_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"


def fetch(limit: int = 100) -> list[RawIOC]:
    try:
        resp = http_get(RECENT_JSON_URL)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("urlhaus fetch failed: %s", exc)
        return []

    results: list[RawIOC] = []

    # Payload is a dict keyed by internal id -> list of one or more entry dicts
    try:
        entries = []
        if isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, list):
                    entries.extend(value)
                elif isinstance(value, dict):
                    entries.append(value)
        elif isinstance(payload, list):
            entries = payload
    except Exception as exc:  # noqa: BLE001
        logger.warning("urlhaus payload parsing failed: %s", exc)
        return []

    for entry in entries[:limit]:
        try:
            url = entry.get("url")
            if not url:
                continue
            threat_raw = entry.get("threat", "malware")
            status = (entry.get("url_status") or "").lower()
            confidence = 80 if status == "online" else 60

            tags = entry.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            results.append(
                RawIOC(
                    ioc_value=url,
                    ioc_type="url",
                    threat_type=normalize_threat_type(threat_raw),
                    source_feed=FEED_NAME,
                    confidence=confidence,
                    malware_family=None,
                    first_seen=entry.get("dateadded"),
                    tags=list(tags),
                    reference_url=entry.get("urlhaus_reference"),
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("urlhaus: skipping malformed entry: %s", exc)
            continue

    logger.info("urlhaus: parsed %d IOCs", len(results))
    return results
