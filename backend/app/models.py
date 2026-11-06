from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ThreatEvent(Base):
    """A single indicator of compromise (IOC) observed by one of the feeds."""

    __tablename__ = "threat_events"
    __table_args__ = (
        Index("ix_threat_events_ioc_value", "ioc_value"),
        Index("ix_threat_events_severity", "severity_score"),
        Index("ix_threat_events_first_seen", "first_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    ioc_value: Mapped[str] = mapped_column(String(512), unique=True)
    ioc_type: Mapped[str] = mapped_column(String(32))  # ip | domain | url | hash

    threat_type: Mapped[str] = mapped_column(String(64))  # malware, phishing, botnet, ...
    malware_family: Mapped[str | None] = mapped_column(String(128), nullable=True)

    source_feed: Mapped[str] = mapped_column(String(64))  # urlhaus, threatfox, demo-simulator...
    confidence: Mapped[int] = mapped_column(Integer, default=50)

    severity_score: Mapped[int] = mapped_column(Integer, default=0)
    severity_label: Mapped[str] = mapped_column(String(16), default="low")

    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    asn: Mapped[str | None] = mapped_column(String(128), nullable=True)

    tags: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)

    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    times_reported: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "threat_type": self.threat_type,
            "malware_family": self.malware_family,
            "source_feed": self.source_feed,
            "confidence": self.confidence,
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "country": self.country,
            "country_code": self.country_code,
            "lat": self.lat,
            "lon": self.lon,
            "asn": self.asn,
            "tags": self.tags or [],
            "mitre_techniques": self.mitre_techniques or [],
            "reference_url": self.reference_url,
            "is_synthetic": self.is_synthetic,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "times_reported": self.times_reported,
        }


class CVEEntry(Base):
    """A tracked CVE, optionally cross-referenced against CISA's Known Exploited Vulns list."""

    __tablename__ = "cve_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    vendor_project: Mapped[str | None] = mapped_column(String(256), nullable=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)

    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)

    published_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "is_kev": self.is_kev,
            "kev_due_date": self.kev_due_date,
            "ransomware_use": self.ransomware_use,
            "published_date": self.published_date,
            "is_synthetic": self.is_synthetic,
        }


class AlertLog(Base):
    """Record of every alert CTIP attempted to send (for the alerting history panel)."""

    __tablename__ = "alert_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    channel: Mapped[str] = mapped_column(String(32))  # slack | email | log
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "message": self.message,
            "severity": self.severity,
            "channel": self.channel,
            "success": self.success,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }


class FeedStatus(Base):
    """Tracks the health/last-run status of each feed connector, shown on the dashboard."""

    __tablename__ = "feed_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_name: Mapped[str] = mapped_column(String(64), unique=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success: Mapped[bool] = mapped_column(Boolean, default=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    events_ingested: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "feed_name": self.feed_name,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_success": self.last_success,
            "last_error": self.last_error,
            "events_ingested": self.events_ingested,
        }
