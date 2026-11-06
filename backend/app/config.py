"""
Central configuration for CTIP.

All values are overridable via environment variables or a `.env` file in
the backend/ directory (see .env.example). Nothing here requires secrets
to run — the platform works fully in DEMO_MODE with zero configuration.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv

    # Load backend/.env if present (does nothing if the file is missing)
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:  # pragma: no cover - python-dotenv is a soft dependency
    pass


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    # --- General ---
    APP_NAME: str = "Cyber Threat Intelligence Platform"
    ENV: str = os.getenv("CTIP_ENV", "development")

    # If true (default), the aggregator will backfill with a clearly-labeled
    # synthetic feed whenever live sources return too few results, so the
    # dashboard is always populated (e.g. on a laptop with no internet, or
    # if a free upstream API is temporarily down/rate-limited).
    DEMO_MODE: bool = _bool("CTIP_DEMO_MODE", True)
    MIN_LIVE_EVENTS_BEFORE_DEMO_FILL: int = _int("CTIP_MIN_LIVE_EVENTS", 5)

    # How long a threat event is kept after its last sighting before being
    # pruned, so a long-running instance doesn't grow its DB forever (this
    # matters most in demo mode, which mints ~40 brand-new synthetic IOCs
    # every refresh cycle). 0 or negative disables pruning entirely.
    EVENT_RETENTION_DAYS: int = _int("CTIP_EVENT_RETENTION_DAYS", 30)

    # --- Database ---
    # DATA_DIR defaults to backend/data/ (created automatically). In Docker
    # this is mounted as a named volume so the SQLite DB survives restarts.
    DATA_DIR: Path = Path(os.getenv("CTIP_DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE_URL: str = os.getenv("CTIP_DATABASE_URL", f"sqlite:///{DATA_DIR / 'ctip.db'}")

    # --- Scheduler ---
    FEED_REFRESH_MINUTES: int = _int("CTIP_FEED_REFRESH_MINUTES", 10)
    CVE_REFRESH_MINUTES: int = _int("CTIP_CVE_REFRESH_MINUTES", 60)

    # --- Optional API keys (feeds work without these, but some unlock more
    # data / higher rate limits when provided) ---
    OTX_API_KEY: Optional[str] = os.getenv("CTIP_OTX_API_KEY") or None
    NVD_API_KEY: Optional[str] = os.getenv("CTIP_NVD_API_KEY") or None
    # Free registration at https://auth.abuse.ch/ — required (as of 2025+)
    # for ThreatFox and MalwareBazaar. URLhaus's bulk JSON export does not
    # need one. Without a key, those two feeds are skipped gracefully.
    ABUSECH_AUTH_KEY: Optional[str] = os.getenv("CTIP_ABUSECH_AUTH_KEY") or None
    # Free key from https://cloud.maptiler.com (100k tile loads/month, no
    # card required) for a proper dark cartographic style on the threat
    # map. Without one, the map falls back to plain OpenStreetMap tiles
    # with a CSS dark-mode filter — functional but visually flatter.
    MAPTILER_API_KEY: Optional[str] = os.getenv("CTIP_MAPTILER_API_KEY") or None

    # --- GeoIP ---
    # ip-api.com free batch endpoint (no key required, rate-limited to
    # 45 req/min). Swap for a commercial provider in geoip.py if desired.
    GEOIP_BATCH_URL: str = "http://ip-api.com/batch"
    GEOIP_CACHE_TTL_HOURS: int = 24

    # --- Alerting (all optional; alerts silently no-op if unset) ---
    SLACK_WEBHOOK_URL: Optional[str] = os.getenv("CTIP_SLACK_WEBHOOK_URL") or None
    ALERT_SEVERITY_THRESHOLD: int = _int("CTIP_ALERT_SEVERITY_THRESHOLD", 85)

    SMTP_HOST: Optional[str] = os.getenv("CTIP_SMTP_HOST") or None
    SMTP_PORT: int = _int("CTIP_SMTP_PORT", 587)
    SMTP_USER: Optional[str] = os.getenv("CTIP_SMTP_USER") or None
    SMTP_PASSWORD: Optional[str] = os.getenv("CTIP_SMTP_PASSWORD") or None
    ALERT_EMAIL_TO: Optional[str] = os.getenv("CTIP_ALERT_EMAIL_TO") or None

    # --- CORS (so the dashboard can be embedded from your own website) ---
    CORS_ALLOW_ORIGINS: list[str] = [
        o.strip() for o in os.getenv("CTIP_CORS_ORIGINS", "*").split(",") if o.strip()
    ]

    # --- HTTP client ---
    HTTP_TIMEOUT_SECONDS: int = _int("CTIP_HTTP_TIMEOUT", 15)
    USER_AGENT: str = "CTIP-ThreatIntelBot/1.0 (+https://github.com/)"


settings = Settings()
