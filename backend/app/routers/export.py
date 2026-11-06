from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent

router = APIRouter(prefix="/api/export", tags=["export"])

CSV_FIELDS = [
    "ioc_value", "ioc_type", "threat_type", "malware_family", "source_feed",
    "confidence", "severity_score", "severity_label", "country", "country_code",
    "first_seen", "last_seen", "times_reported", "is_synthetic",
]


@router.get("/threats.csv")
def export_threats_csv(db: Session = Depends(get_db), limit: int = Query(1000, le=5000)):
    events = db.query(ThreatEvent).order_by(ThreatEvent.last_seen.desc()).limit(limit).all()

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for e in events:
        row = e.to_dict()
        writer.writerow({k: row.get(k) for k in CSV_FIELDS})
    buffer.seek(0)

    filename = f"ctip_threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/threats.json")
def export_threats_json(db: Session = Depends(get_db), limit: int = Query(1000, le=5000)):
    events = db.query(ThreatEvent).order_by(ThreatEvent.last_seen.desc()).limit(limit).all()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(events),
        "events": [e.to_dict() for e in events],
    }
    filename = f"ctip_threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.json"
    return StreamingResponse(
        iter([json.dumps(payload, indent=2, default=str)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
