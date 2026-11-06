from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent
from app.schemas import CountryAggregateOut, MapPointOut

router = APIRouter(prefix="/api/map", tags=["map"])


@router.get("/points", response_model=list[MapPointOut])
def map_points(db: Session = Depends(get_db), limit: int = Query(500, ge=1, le=2000)):
    events = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.lat.isnot(None), ThreatEvent.lon.isnot(None))
        .order_by(ThreatEvent.last_seen.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "lat": e.lat,
            "lon": e.lon,
            "country": e.country,
            "country_code": e.country_code,
            "severity_label": e.severity_label,
            "severity_score": e.severity_score,
            "threat_type": e.threat_type,
            "ioc_value": e.ioc_value,
            "is_synthetic": e.is_synthetic,
        }
        for e in events
    ]


@router.get("/countries", response_model=list[CountryAggregateOut])
def map_countries(db: Session = Depends(get_db)):
    events = db.query(ThreatEvent).filter(ThreatEvent.country_code.isnot(None)).all()
    agg: dict[str, dict] = defaultdict(lambda: {"count": 0, "max_severity": 0, "country": None})
    for e in events:
        bucket = agg[e.country_code]
        bucket["count"] += 1
        bucket["max_severity"] = max(bucket["max_severity"], e.severity_score)
        bucket["country"] = e.country

    result = [
        {
            "country": data["country"],
            "country_code": code,
            "count": data["count"],
            "max_severity": data["max_severity"],
        }
        for code, data in agg.items()
    ]
    return sorted(result, key=lambda r: r["count"], reverse=True)
