"""
Resolves IP addresses to approximate geographic coordinates for the threat
map, using ip-api.com's free batch endpoint (no key required, 45 req/min,
up to 100 IPs per batch call). Results are cached in-process to stay well
under the rate limit and avoid redundant lookups across refresh cycles.

For domains/URLs/hashes (which have no IP to geolocate), the aggregator
either resolves the hostname first or leaves lat/lon null and the map
simply omits that marker (it still appears in the feed table).
"""
from __future__ import annotations

import concurrent.futures
import socket
import time
from typing import Optional

import requests

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("ctip.geoip")

_cache: dict[str, tuple[float, dict]] = {}  # ip -> (expires_at_epoch, result)
_BATCH_SIZE = 100


def _cache_get(ip: str) -> Optional[dict]:
    entry = _cache.get(ip)
    if not entry:
        return None
    expires_at, result = entry
    if time.time() > expires_at:
        _cache.pop(ip, None)
        return None
    return result


def _cache_put(ip: str, result: dict) -> None:
    ttl = settings.GEOIP_CACHE_TTL_HOURS * 3600
    _cache[ip] = (time.time() + ttl, result)


def batch_lookup(ips: list[str]) -> dict[str, dict]:
    """
    Resolve a list of IPs to {country, country_code, lat, lon, asn}.
    Returns a dict keyed by IP; IPs that fail to resolve are omitted.
    """
    ips = list(dict.fromkeys(ip for ip in ips if ip))  # dedupe, preserve order
    resolved: dict[str, dict] = {}

    to_query = []
    for ip in ips:
        cached = _cache_get(ip)
        if cached:
            resolved[ip] = cached
        else:
            to_query.append(ip)

    for i in range(0, len(to_query), _BATCH_SIZE):
        chunk = to_query[i : i + _BATCH_SIZE]
        payload = [{"query": ip, "fields": "status,country,countryCode,lat,lon,as,query"} for ip in chunk]
        try:
            resp = requests.post(
                settings.GEOIP_BATCH_URL,
                json=payload,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            batch_result = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("geoip batch lookup failed for %d IPs: %s", len(chunk), exc)
            continue

        for entry in batch_result or []:
            if entry.get("status") != "success":
                continue
            ip = entry.get("query")
            result = {
                "country": entry.get("country"),
                "country_code": entry.get("countryCode"),
                "lat": entry.get("lat"),
                "lon": entry.get("lon"),
                "asn": entry.get("as"),
            }
            resolved[ip] = result
            _cache_put(ip, result)

    return resolved


def resolve_hostnames(hostnames: list[str], overall_timeout: float = 15.0, max_workers: int = 25) -> dict[str, str]:
    """
    Resolve a batch of hostnames to their first IPv4 address, so domain/URL
    IOCs (the majority of what ThreatFox/URLhaus report — not raw IPs) can
    still be plotted on the map and counted per-country.

    Runs lookups concurrently with a bounded overall wait time: DNS calls
    don't reliably honor a per-call timeout in Python's stdlib, so instead
    of risking one slow/unresponsive resolver stalling an entire ingestion
    cycle, we wait up to `overall_timeout` seconds total and simply accept
    whichever lookups finished in time. Any stragglers are abandoned
    (their threads finish or die in the background) rather than blocking.
    """
    hostnames = list(dict.fromkeys(h for h in hostnames if h))[:200]  # cap batch size
    resolved: dict[str, str] = {}
    if not hostnames:
        return resolved

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {executor.submit(socket.gethostbyname, h): h for h in hostnames}
        done, _pending = concurrent.futures.wait(futures, timeout=overall_timeout)
        for future in done:
            host = futures[future]
            try:
                resolved[host] = future.result()
            except Exception:  # noqa: BLE001 - unresolvable host, just skip it
                continue
    finally:
        executor.shutdown(wait=False)

    return resolved
