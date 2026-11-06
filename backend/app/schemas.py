from __future__ import annotations

from pydantic import BaseModel


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str


class ThreatEventOut(BaseModel):
    id: int
    ioc_value: str
    ioc_type: str
    threat_type: str
    malware_family: str | None = None
    source_feed: str
    confidence: int
    severity_score: int
    severity_label: str
    country: str | None = None
    country_code: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None
    tags: list[str] = []
    mitre_techniques: list[dict] = []
    reference_url: str | None = None
    is_synthetic: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    times_reported: int = 1


class CVEOut(BaseModel):
    id: int
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    vendor_project: str | None = None
    product: str | None = None
    is_kev: bool = False
    kev_due_date: str | None = None
    ransomware_use: bool = False
    published_date: str | None = None
    is_synthetic: bool = False


class MapPointOut(BaseModel):
    lat: float
    lon: float
    country: str | None = None
    country_code: str | None = None
    severity_label: str
    severity_score: int
    threat_type: str
    ioc_value: str
    is_synthetic: bool = False


class CountryAggregateOut(BaseModel):
    country: str | None = None
    country_code: str | None = None
    count: int
    max_severity: int


class ThreatTypeCount(BaseModel):
    threat_type: str
    count: int


class TrendPoint(BaseModel):
    bucket: str
    count: int


class StatsOverviewOut(BaseModel):
    total_iocs: int
    active_last_24h: int
    critical_count: int
    countries_affected: int
    kev_count: int
    demo_mode_active: bool
    synthetic_count: int
    top_threat_types: list[ThreatTypeCount]
    top_countries: list[CountryAggregateOut]
    severity_trend: list[TrendPoint]
    ioc_type_breakdown: list[ThreatTypeCount]


class FeedStatusOut(BaseModel):
    feed_name: str
    last_run_at: str | None = None
    last_success: bool
    last_error: str | None = None
    events_ingested: int


class MitreMatrixEntry(BaseModel):
    id: str
    name: str
    tactic: str
    count: int


class AlertLogOut(BaseModel):
    id: int
    message: str
    severity: str
    channel: str
    success: bool
    sent_at: str | None = None


class SearchResultOut(BaseModel):
    threats: list[ThreatEventOut]
    cves: list[CVEOut]


class CampaignOut(BaseModel):
    id: str
    kind: str  # malware_family | shared_infrastructure
    label: str
    member_count: int
    countries: list[str] = []
    threat_types: list[str] = []
    max_severity: int
    first_seen: str | None = None
    last_seen: str | None = None


class CampaignGraphNode(BaseModel):
    id: int
    ioc_value: str | None = None
    ioc_type: str | None = None
    threat_type: str | None = None
    severity_label: str | None = None
    severity_score: int | None = None
    country: str | None = None
    campaign_id: str


class CampaignGraphEdge(BaseModel):
    source: int
    target: int


class CampaignGraphOut(BaseModel):
    nodes: list[CampaignGraphNode]
    edges: list[CampaignGraphEdge]


class CampaignsResponseOut(BaseModel):
    campaigns: list[CampaignOut]
    graph: CampaignGraphOut
    ungrouped_count: int
