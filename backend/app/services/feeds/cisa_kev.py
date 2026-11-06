"""
CISA Known Exploited Vulnerabilities (KEV) Catalog — free, no-auth-required
JSON feed of CVEs confirmed to be actively exploited in the wild. This is
one of the highest-signal, lowest-noise threat feeds that exists: every
entry here is a "patch this now" item, not a theoretical risk.

Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
JSON:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

from app.services.feeds.base import http_get, logger

FEED_NAME = "cisa_kev"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(limit: int = 100) -> list[dict]:
    """Returns a list of normalized CVE dicts (see app.models.CVEEntry fields)."""
    try:
        resp = http_get(KEV_URL)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("cisa_kev fetch failed: %s", exc)
        return []

    vulns = (payload or {}).get("vulnerabilities") or []
    # Most recently added first
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)

    results = []
    for v in vulns[:limit]:
        try:
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            results.append(
                {
                    "cve_id": cve_id,
                    "description": v.get("shortDescription"),
                    "cvss_score": None,  # KEV doesn't publish CVSS; NVD connector fills this in
                    "severity": "critical",  # actively exploited => treat as critical by default
                    "vendor_project": v.get("vendorProject"),
                    "product": v.get("product"),
                    "is_kev": True,
                    "kev_due_date": v.get("dueDate"),
                    "ransomware_use": str(v.get("knownRansomwareCampaignUse", "")).lower()
                    == "known",
                    "published_date": v.get("dateAdded"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("cisa_kev: skipping malformed entry: %s", exc)
            continue

    logger.info("cisa_kev: parsed %d entries", len(results))
    return results
