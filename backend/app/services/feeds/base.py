from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("ctip.feeds")


@dataclass
class RawIOC:
    """Normalized shape every feed connector converts its API response into,
    before it reaches the enrichment/aggregation stage."""

    ioc_value: str
    ioc_type: str  # ip | domain | url | hash
    threat_type: str
    source_feed: str
    confidence: int = 50
    malware_family: str | None = None
    country_code: str | None = None  # filled in later by geoip if unknown
    first_seen: str | None = None  # ISO8601 string, feed-reported
    times_reported: int = 1
    tags: list[str] = field(default_factory=list)
    reference_url: str | None = None


def http_get(url: str, params: dict | None = None, headers: dict | None = None) -> requests.Response:
    merged_headers = {"User-Agent": settings.USER_AGENT}
    if headers:
        merged_headers.update(headers)
    return requests.get(
        url, params=params, headers=merged_headers, timeout=settings.HTTP_TIMEOUT_SECONDS
    )


def http_post(url: str, data: Any = None, json: Any = None, headers: dict | None = None) -> requests.Response:
    merged_headers = {"User-Agent": settings.USER_AGENT}
    if headers:
        merged_headers.update(headers)
    return requests.post(
        url, data=data, json=json, headers=merged_headers, timeout=settings.HTTP_TIMEOUT_SECONDS
    )
