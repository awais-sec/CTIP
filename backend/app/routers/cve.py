from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CVEEntry
from app.schemas import CVEOut

router = APIRouter(prefix="/api/cve", tags=["cve"])


@router.get("", response_model=list[CVEOut])
def list_cves(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=300),
    kev_only: bool = False,
    min_score: float | None = None,
):
    query = db.query(CVEEntry)
    if kev_only:
        query = query.filter(CVEEntry.is_kev.is_(True))
    if min_score is not None:
        query = query.filter(CVEEntry.cvss_score >= min_score)

    entries = query.order_by(CVEEntry.published_date.desc()).limit(limit).all()
    return [e.to_dict() for e in entries]
