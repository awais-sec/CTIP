from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CVEEntry, ThreatEvent
from app.schemas import SearchResultOut

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("", response_model=SearchResultOut)
def search(q: str = Query(..., min_length=2), db: Session = Depends(get_db)):
    like = f"%{q}%"

    threats = (
        db.query(ThreatEvent)
        .filter(
            (ThreatEvent.ioc_value.ilike(like))
            | (ThreatEvent.malware_family.ilike(like))
            | (ThreatEvent.threat_type.ilike(like))
        )
        .order_by(ThreatEvent.last_seen.desc())
        .limit(50)
        .all()
    )

    cves = (
        db.query(CVEEntry)
        .filter((CVEEntry.cve_id.ilike(like)) | (CVEEntry.description.ilike(like)) | (CVEEntry.product.ilike(like)))
        .order_by(CVEEntry.published_date.desc())
        .limit(50)
        .all()
    )

    return {
        "threats": [t.to_dict() for t in threats],
        "cves": [c.to_dict() for c in cves],
    }
