"""
NIST National Vulnerability Database (NVD) — free CVE feed (an API key is
optional but recommended for higher rate limits; without one NVD allows a
handful of requests per 30s, which is enough for a periodic refresh job).

Docs: https://nvd.nist.gov/developers/vulnerabilities
Endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import settings
from app.services.feeds.base import http_get, logger

FEED_NAME = "nvd_cve"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cvss(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, (severity.lower() if severity else None)
    return None, None


def fetch(hours: int = 48, limit: int = 100) -> list[dict]:
    """Returns a list of normalized CVE dicts for recently published CVEs."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 2000),
    }
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    try:
        resp = http_get(API_URL, params=params, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("nvd_cve fetch failed: %s", exc)
        return []

    vulns = (payload or {}).get("vulnerabilities") or []
    results = []
    for item in vulns[:limit]:
        try:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions") or []
            description = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"), None
            )
            score, severity = _extract_cvss(cve)

            results.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": score,
                    "severity": severity or ("high" if (score or 0) >= 7 else "medium"),
                    "vendor_project": None,
                    "product": None,
                    "is_kev": False,
                    "kev_due_date": None,
                    "ransomware_use": False,
                    "published_date": cve.get("published"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("nvd_cve: skipping malformed entry: %s", exc)
            continue

    logger.info("nvd_cve: parsed %d entries", len(results))
    return results
