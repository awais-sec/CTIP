from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent
from app.schemas import MitreMatrixEntry
from app.services.mitre_map import all_known_techniques

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/matrix", response_model=list[MitreMatrixEntry])
def mitre_matrix(db: Session = Depends(get_db)):
    events = db.query(ThreatEvent.mitre_techniques).all()
    counts: Counter[str] = Counter()
    for (techniques,) in events:
        for t in techniques or []:
            tid = t.get("id") if isinstance(t, dict) else None
            if tid:
                counts[tid] += 1

    catalog = all_known_techniques()
    return [
        {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "count": counts.get(t["id"], 0)}
        for t in catalog
    ]
