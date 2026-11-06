from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent
from app.schemas import ThreatEventOut

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("", response_model=list[ThreatEventOut])
def list_threats(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    threat_type: str | None = None,
    ioc_type: str | None = None,
    severity_label: str | None = None,
    country_code: str | None = None,
    source_feed: str | None = None,
    q: str | None = Query(None, description="Free-text search over the IOC value"),
):
    query = db.query(ThreatEvent)
    if threat_type:
        query = query.filter(ThreatEvent.threat_type == threat_type)
    if ioc_type:
        query = query.filter(ThreatEvent.ioc_type == ioc_type)
    if severity_label:
        query = query.filter(ThreatEvent.severity_label == severity_label)
    if country_code:
        query = query.filter(ThreatEvent.country_code == country_code.upper())
    if source_feed:
        query = query.filter(ThreatEvent.source_feed == source_feed)
    if q:
        query = query.filter(ThreatEvent.ioc_value.ilike(f"%{q}%"))

    events = query.order_by(desc(ThreatEvent.last_seen)).limit(limit).all()
    return [e.to_dict() for e in events]


@router.get("/{event_id}", response_model=ThreatEventOut)
def get_threat(event_id: int, db: Session = Depends(get_db)):
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).one_or_none()
    if not event:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Threat event not found")
    return event.to_dict()
