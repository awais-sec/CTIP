from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AlertLog, CVEEntry, FeedStatus, ThreatEvent
from app.schemas import AlertLogOut, FeedStatusOut, StatsOverviewOut

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/overview", response_model=StatsOverviewOut)
def overview(db: Session = Depends(get_db)):
    events = db.query(ThreatEvent).all()
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)

    total = len(events)
    active_24h = 0
    critical = 0
    synthetic_count = 0
    countries: set[str] = set()
    type_counter: Counter[str] = Counter()
    ioc_type_counter: Counter[str] = Counter()
    country_agg: dict[str, dict] = defaultdict(lambda: {"count": 0, "max_severity": 0, "country": None})
    trend_buckets: dict[str, int] = defaultdict(int)

    for e in events:
        last_seen = e.last_seen
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if last_seen and last_seen >= cutoff_24h:
            active_24h += 1
        if e.severity_label == "critical":
            critical += 1
        if e.is_synthetic:
            synthetic_count += 1
        if e.country_code:
            countries.add(e.country_code)
            bucket = country_agg[e.country_code]
            bucket["count"] += 1
            bucket["max_severity"] = max(bucket["max_severity"], e.severity_score)
            bucket["country"] = e.country
        type_counter[e.threat_type] += 1
        ioc_type_counter[e.ioc_type] += 1

        first_seen = e.first_seen
        if first_seen:
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            bucket_key = first_seen.strftime("%Y-%m-%d %H:00")
            trend_buckets[bucket_key] += 1

    top_countries = sorted(
        (
            {"country": v["country"], "country_code": k, "count": v["count"], "max_severity": v["max_severity"]}
            for k, v in country_agg.items()
        ),
        key=lambda r: r["count"],
        reverse=True,
    )[:10]

    trend = sorted(
        ({"bucket": k, "count": v} for k, v in trend_buckets.items()), key=lambda r: r["bucket"]
    )[-24:]

    # Counted server-side against the full table, not the small page the
    # CVE watchlist panel fetches — that page alone would undercount this.
    kev_count = db.query(CVEEntry).filter(CVEEntry.is_kev.is_(True)).count()

    return {
        "total_iocs": total,
        "active_last_24h": active_24h,
        "critical_count": critical,
        "countries_affected": len(countries),
        "kev_count": kev_count,
        # Reflects whether synthetic demo data is actually present in the
        # current dataset right now — not just whether the DEMO_MODE
        # feature flag is turned on (which defaults to true as a fallback
        # capability, even when every event ends up being real).
        "demo_mode_active": synthetic_count > 0,
        "synthetic_count": synthetic_count,
        "top_threat_types": [{"threat_type": t, "count": c} for t, c in type_counter.most_common(8)],
        "top_countries": top_countries,
        "severity_trend": trend,
        "ioc_type_breakdown": [{"threat_type": t, "count": c} for t, c in ioc_type_counter.most_common()],
    }


@router.get("/feeds", response_model=list[FeedStatusOut])
def feed_status(db: Session = Depends(get_db)):
    statuses = db.query(FeedStatus).all()
    return [s.to_dict() for s in statuses]


@router.get("/alerts", response_model=list[AlertLogOut])
def alert_history(db: Session = Depends(get_db), limit: int = 50):
    alerts = db.query(AlertLog).order_by(AlertLog.sent_at.desc()).limit(limit).all()
    return [a.to_dict() for a in alerts]
