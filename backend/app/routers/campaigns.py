from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent
from app.schemas import CampaignsResponseOut
from app.services.campaign_correlation import correlate_events

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])


@router.get("", response_model=CampaignsResponseOut)
def list_campaigns(
    db: Session = Depends(get_db),
    limit: int = Query(300, ge=10, le=1000, description="Most severe/recent IOCs to consider"),
    min_cluster_size: int = Query(2, ge=2, le=20),
):
    events = (
        db.query(ThreatEvent)
        .order_by(ThreatEvent.severity_score.desc(), ThreatEvent.last_seen.desc())
        .limit(limit)
        .all()
    )
    return correlate_events([e.to_dict() for e in events], min_cluster_size=min_cluster_size)
