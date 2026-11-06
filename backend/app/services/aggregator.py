"""
The aggregator is the heart of CTIP's ingestion pipeline. On every scheduled
run it:

  1. Pulls raw IOCs from every live feed connector (URLhaus, ThreatFox,
     MalwareBazaar, optionally OTX)
  2. If live feeds returned too little (no internet, feed down, rate
     limited) tops up with clearly-labeled synthetic demo data
  3. Batch-resolves IP-based IOCs to lat/lon via GeoIP
  4. Scores each IOC's severity and maps it to MITRE ATT&CK techniques
  5. Upserts into the database (dedup by IOC value; repeated sightings
     bump times_reported and refresh last_seen/severity)
  6. Fires alerts for anything crossing the critical threshold
  7. Broadcasts new/updated events to connected dashboards over WebSocket

CVEs (CISA KEV + NVD) are refreshed on a separate, slower cadence via
`refresh_cves()`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from app.config import settings
from app.database import session_scope
from app.models import CVEEntry, FeedStatus, ThreatEvent
from app.services import alerting, geoip
from app.services.enrichment import compute_severity
from app.services.feeds import cisa_kev, demo_simulator, malwarebazaar, nvd_cve, otx, threatfox, urlhaus
from app.services.feeds.base import RawIOC
from app.services.mitre_map import get_techniques
from app.services.ws_manager import manager
from app.utils.logger import get_logger

logger = get_logger("ctip.aggregator")

LIVE_FEEDS = [urlhaus, threatfox, malwarebazaar, otx]


def _hours_since(iso_str: str | None) -> float:
    if not iso_str:
        return 0.0
    try:
        # Normalize common formats (with/without timezone, abuse.ch's "YYYY-MM-DD HH:MM:SS UTC")
        cleaned = iso_str.replace("Z", "+00:00").replace(" UTC", "+00:00").replace(" ", "T", 1)
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(0.0, delta.total_seconds() / 3600.0)
    except Exception:  # noqa: BLE001
        return 0.0


def _extract_hostname(raw: RawIOC) -> str | None:
    """Best-effort extraction of something DNS-resolvable from an IOC, so
    domain/URL indicators (the majority of real feed data — not just raw
    IPs) can still be geolocated for the map/country stats."""
    if raw.ioc_type == "domain":
        return raw.ioc_value
    if raw.ioc_type == "url":
        try:
            host = urlparse(raw.ioc_value).hostname
            return host
        except Exception:  # noqa: BLE001
            return None
    return None  # ip type is handled directly; hash type has no network location


def _update_feed_status(feed_name: str, success: bool, count: int, error: str | None = None) -> None:
    with session_scope() as db:
        status = db.query(FeedStatus).filter_by(feed_name=feed_name).one_or_none()
        if not status:
            status = FeedStatus(feed_name=feed_name)
            db.add(status)
        status.last_run_at = datetime.now(timezone.utc)
        status.last_success = success
        status.last_error = error
        status.events_ingested = count


def _collect_live_events() -> list[RawIOC]:
    events: list[RawIOC] = []
    for feed_module in LIVE_FEEDS:
        name = getattr(feed_module, "FEED_NAME", feed_module.__name__)
        try:
            batch = feed_module.fetch()
            events.extend(batch)
            _update_feed_status(name, success=True, count=len(batch))
        except Exception as exc:  # noqa: BLE001
            logger.error("feed %s raised an exception: %s", name, exc)
            _update_feed_status(name, success=False, count=0, error=str(exc))
    return events


def _enrich_and_upsert(raw_events: list[RawIOC], synthetic: bool = False) -> list[dict]:
    """Enrich raw IOCs (geo, severity, MITRE) and upsert into the DB.
    Returns dicts for events that are new or materially changed, for
    broadcast/alerting purposes."""
    if not raw_events:
        return []

    # Batch-resolve geo for real (non-synthetic) IOCs. IP-type IOCs go
    # straight to GeoIP; domain/URL-type IOCs are DNS-resolved to an IP
    # first (hash-type IOCs have no network location and are skipped).
    ip_targets: dict[str, str] = {}  # ioc_value -> ip to geolocate
    if not synthetic:
        hostnames_to_resolve: list[str] = []
        for e in raw_events:
            if e.ioc_type == "ip":
                ip_targets[e.ioc_value] = e.ioc_value
            else:
                host = _extract_hostname(e)
                if host:
                    hostnames_to_resolve.append(host)

        if hostnames_to_resolve:
            host_to_ip = geoip.resolve_hostnames(hostnames_to_resolve)
            for e in raw_events:
                if e.ioc_value in ip_targets:
                    continue
                host = _extract_hostname(e)
                if host and host in host_to_ip:
                    ip_targets[e.ioc_value] = host_to_ip[host]

    geo_lookup = geoip.batch_lookup(list(set(ip_targets.values()))) if ip_targets else {}

    changed: list[dict] = []

    with session_scope() as db:
        for raw in raw_events:
            existing = db.query(ThreatEvent).filter_by(ioc_value=raw.ioc_value).one_or_none()
            is_new = existing is None
            previous_label = existing.severity_label if existing else None

            hours_ago = _hours_since(raw.first_seen)
            times_reported = (existing.times_reported + 1) if existing else raw.times_reported
            severity = compute_severity(
                raw.threat_type, confidence=raw.confidence, hours_since_seen=hours_ago,
                times_reported=times_reported,
            )
            techniques = get_techniques(raw.threat_type, raw.tags)

            if synthetic:
                geo = demo_simulator.generate_synthetic_geo()
            else:
                resolved_ip = ip_targets.get(raw.ioc_value)
                geo = geo_lookup.get(resolved_ip, {}) if resolved_ip else {}

            now = datetime.now(timezone.utc)

            if existing:
                existing.last_seen = now
                existing.times_reported = times_reported
                existing.confidence = max(existing.confidence, raw.confidence)
                existing.severity_score = severity.score
                existing.severity_label = severity.label
                existing.mitre_techniques = techniques
                if geo.get("lat") is not None:
                    existing.country = geo.get("country") or existing.country
                    existing.country_code = geo.get("country_code") or existing.country_code
                    existing.lat = geo.get("lat", existing.lat)
                    existing.lon = geo.get("lon", existing.lon)
                    existing.asn = geo.get("asn") or existing.asn
                record = existing
            else:
                record = ThreatEvent(
                    ioc_value=raw.ioc_value,
                    ioc_type=raw.ioc_type,
                    threat_type=raw.threat_type,
                    malware_family=raw.malware_family,
                    source_feed=raw.source_feed,
                    confidence=raw.confidence,
                    severity_score=severity.score,
                    severity_label=severity.label,
                    country=geo.get("country"),
                    country_code=geo.get("country_code"),
                    lat=geo.get("lat"),
                    lon=geo.get("lon"),
                    asn=geo.get("asn"),
                    tags=raw.tags,
                    mitre_techniques=techniques,
                    reference_url=raw.reference_url,
                    is_synthetic=synthetic,
                    times_reported=times_reported,
                    first_seen=now,
                    last_seen=now,
                )
                db.add(record)

            db.flush()

            # Only surface genuinely new sightings or ones whose severity
            # bucket actually moved, for broadcast/alerting. Every feed
            # re-reports the same still-active IOCs on every poll cycle, so
            # without this a critical IOC that stays critical for days would
            # re-broadcast over the WebSocket and re-fire Slack/email alerts
            # on every single refresh (every CTIP_FEED_REFRESH_MINUTES) for
            # as long as the source feed keeps listing it.
            if is_new or previous_label != severity.label:
                changed.append(record.to_dict())

    return changed


def refresh_threat_events() -> list[dict]:
    live_events = _collect_live_events()
    logger.info("collected %d live IOCs across all feeds", len(live_events))

    changed = _enrich_and_upsert(live_events, synthetic=False)

    if len(live_events) < settings.MIN_LIVE_EVENTS_BEFORE_DEMO_FILL and settings.DEMO_MODE:
        fill_count = 40 - len(live_events)
        logger.info(
            "live feeds returned only %d events; topping up with %d synthetic demo events",
            len(live_events), max(fill_count, 10),
        )
        synthetic_events = demo_simulator.generate_synthetic_events(n=max(fill_count, 10))
        changed += _enrich_and_upsert(synthetic_events, synthetic=True)

    for event in changed:
        alerting.alert_on_critical_event(event)

    return changed


def refresh_cves() -> list[dict]:
    kev_entries = {}
    try:
        for e in cisa_kev.fetch():
            kev_entries[e["cve_id"]] = e
        _update_feed_status("cisa_kev", True, len(kev_entries))
    except Exception as exc:  # noqa: BLE001
        logger.error("cisa_kev refresh failed: %s", exc)
        _update_feed_status("cisa_kev", False, 0, str(exc))

    nvd_entries = {}
    try:
        for e in nvd_cve.fetch():
            nvd_entries[e["cve_id"]] = e
        _update_feed_status("nvd_cve", True, len(nvd_entries))
    except Exception as exc:  # noqa: BLE001
        logger.error("nvd_cve refresh failed: %s", exc)
        _update_feed_status("nvd_cve", False, 0, str(exc))

    merged: dict[str, dict] = dict(nvd_entries)
    for cve_id, kev in kev_entries.items():
        base = merged.get(cve_id, {})
        base.update({k: v for k, v in kev.items() if v is not None})
        base["cve_id"] = cve_id
        base.setdefault("cvss_score", None)
        merged[cve_id] = base

    if len(merged) < 3 and settings.DEMO_MODE:
        logger.info("too few live CVEs; topping up with synthetic demo CVEs")
        for e in demo_simulator.generate_synthetic_cves():
            merged[e["cve_id"]] = e

    changed = []
    with session_scope() as db:
        for cve_id, data in merged.items():
            existing = db.query(CVEEntry).filter_by(cve_id=cve_id).one_or_none()
            if existing:
                for field in (
                    "description", "cvss_score", "severity", "vendor_project", "product",
                    "is_kev", "kev_due_date", "ransomware_use", "published_date",
                ):
                    value = data.get(field)
                    if value is not None:
                        setattr(existing, field, value)
                record = existing
            else:
                record = CVEEntry(**{**data, "is_synthetic": data.get("is_synthetic", False)})
                db.add(record)
            db.flush()
            changed.append(record.to_dict())

    return changed


def prune_old_events() -> int:
    """Deletes threat events not seen again since CTIP_EVENT_RETENTION_DAYS
    ago, so a long-running instance's DB doesn't grow forever (demo mode in
    particular mints a steady stream of brand-new synthetic IOCs). Returns
    the number of rows deleted."""
    if settings.EVENT_RETENTION_DAYS <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.EVENT_RETENTION_DAYS)
    with session_scope() as db:
        deleted = (
            db.query(ThreatEvent)
            .filter(ThreatEvent.last_seen < cutoff)
            .delete(synchronize_session=False)
        )
    if deleted:
        logger.info("pruned %d threat events last seen before %s", deleted, cutoff.isoformat())
    return deleted


def broadcast_new_events(events: list[dict], loop: asyncio.AbstractEventLoop | None = None) -> None:
    if not events or loop is None:
        return
    manager.broadcast_threadsafe({"type": "threat_events", "data": events}, loop)
