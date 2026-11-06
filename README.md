# CTIP — Cyber Threat Intelligence Platform

A live, self-hosted threat intelligence dashboard: it pulls real indicators of compromise (IOCs) and vulnerability data from public OSINT feeds, enriches them (GeoIP, severity scoring, MITRE ATT&CK mapping), stores a running history, and streams it all to a real-time web dashboard — a global threat map, live feed, trend charts, an ATT&CK coverage matrix, and a CVE/KEV watchlist.

It's designed to be **cloned and run with zero configuration** (it falls back to clearly-labeled synthetic data if live feeds are unreachable or rate-limited) and to be **embeddable** on your own website via iframe, or run standalone as a portfolio/demo piece.

![status](https://img.shields.io/badge/status-active-2dd4bf) ![python](https://img.shields.io/badge/python-3.11%2B-blue) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Features

- **Live OSINT ingestion** from real, free feeds:
  - [URLhaus](https://urlhaus.abuse.ch/) — malicious URLs used for malware distribution (no auth required)
  - [ThreatFox](https://threatfox.abuse.ch/) — general-purpose IOC feed with per-indicator confidence scores (free [Auth-Key](https://auth.abuse.ch/) required — see Configuration below)
  - [MalwareBazaar](https://bazaar.abuse.ch/) — recently submitted malware sample hashes (free [Auth-Key](https://auth.abuse.ch/) required)
  - [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — CVEs confirmed under active exploitation (no auth required)
  - [NVD](https://nvd.nist.gov/) — recently published CVEs with CVSS scoring (no auth required; optional key for higher rate limits)
  - Optional: [AlienVault OTX](https://otx.alienvault.com/) (bring your own free API key)
- **GeoIP enrichment** — IP-based indicators are plotted on a live world map
- **Severity scoring engine** — a transparent, unit-tested 0–100 score derived from threat type, source confidence, recency, and corroboration volume
- **MITRE ATT&CK mapping** — every indicator is tagged with relevant techniques/tactics, rolled up into a coverage matrix
- **Real-time updates** over WebSocket — new indicators appear in the live feed without a page refresh
- **Alerting** — optional Slack webhook and/or email notifications when a critical-severity indicator is ingested
- **CVE / KEV watchlist** with ransomware-use and due-date flags
- **Search** across IOCs and CVEs
- **CSV/JSON export** of the current threat snapshot
- **Demo mode** — auto-fills with clearly-labeled synthetic data so the dashboard is always populated, even offline or before you've configured anything
- **Interactive API docs** at `/docs` (FastAPI/Swagger)
- Dockerized, one-command deploy

## Screenshots

> Run the app locally and open `http://localhost:8000` — the dashboard is a single static page (`frontend/index.html`), so you can also just drop a screenshot here once you have one for your GitHub README.

## Architecture

```
                 ┌─────────────────────────────────────────────┐
                 │                  Live feeds                  │
                 │  URLhaus · ThreatFox · MalwareBazaar · OTX   │
                 │        CISA KEV · NVD CVE database           │
                 └───────────────────┬───────────────────────────┘
                                     │ (APScheduler, every N min)
                                     ▼
                     ┌───────────────────────────┐
                     │        Aggregator          │
                     │  normalize → dedupe →      │
                     │  GeoIP enrich → severity    │
                     │  score → MITRE ATT&CK map  │
                     └──────────────┬──────────────┘
                                     │
                        ┌────────────┴────────────┐
                        ▼                          ▼
               ┌────────────────┐        ┌──────────────────┐
               │  SQLite / DB    │        │  WebSocket push    │
               │ (SQLAlchemy)   │        │  to dashboards      │
               └───────┬────────┘        └─────────┬──────────┘
                       │                            │
                       ▼                            ▼
              ┌─────────────────────────────────────────┐
              │           FastAPI REST API                │
              │  /api/threats /api/map /api/stats ...     │
              └───────────────────┬─────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │   Dashboard (static HTML/CSS/JS)          │
              │  Leaflet map · Chart.js · live feed        │
              └─────────────────────────────────────────┘
```

**Backend:** Python, FastAPI, SQLAlchemy (SQLite by default, swap in Postgres for production), APScheduler for background refresh jobs, WebSockets for live push.

**Frontend:** Plain HTML/CSS/JS (no build step) using Leaflet for the map and Chart.js for charts, served directly by FastAPI's static file middleware. This keeps the whole thing runnable with `pip install && uvicorn` — nothing to `npm build`, and it's trivial to `<iframe>` into an existing website.

## Project layout

```
CTIP/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app, routers, startup ingestion, static mount
│   │   ├── config.py                # All settings, env-var driven
│   │   ├── database.py              # SQLAlchemy engine/session
│   │   ├── models.py                # ThreatEvent, CVEEntry, AlertLog, FeedStatus
│   │   ├── schemas.py               # Pydantic response models
│   │   ├── scheduler.py             # APScheduler jobs
│   │   ├── routers/                 # threats, map, stats, cve, mitre, search, export, ws
│   │   └── services/
│   │       ├── aggregator.py        # Orchestrates the whole ingestion pipeline
│   │       ├── enrichment.py        # Severity scoring engine (pure functions, unit tested)
│   │       ├── mitre_map.py         # Threat-type → MITRE ATT&CK technique mapping
│   │       ├── geoip.py             # ip-api.com batch GeoIP lookups + caching
│   │       ├── alerting.py          # Slack / email notifications
│   │       ├── ws_manager.py        # WebSocket connection manager
│   │       └── feeds/               # One connector module per data source
│   ├── tests/                       # Unit tests for scoring + ATT&CK mapping
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/{api,map,charts,feed,app}.js
├── docker-compose.yml
└── README.md
```

## Quick start

### Option A — Docker (recommended)

```bash
git clone <your-repo-url> ctip && cd ctip
docker compose up --build
```

Open **http://localhost:8000**.

### Option B — Local Python

```bash
git clone <your-repo-url> ctip && cd ctip/backend
python3 -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # optional — the app runs fine without editing this
uvicorn app.main:app --reload
```

Open **http://localhost:8000**. Interactive API docs are at **http://localhost:8000/docs**.

That's it — on first launch CTIP immediately tries to pull real data from URLhaus/ThreatFox/MalwareBazaar/CISA KEV/NVD. If your network blocks those (or you're just offline), demo mode fills the dashboard with clearly-labeled synthetic data instead, so it's never blank.

## Configuration

All configuration is optional and lives in `backend/.env` (see `.env.example` for the full list):

| Variable | Purpose |
|---|---|
| `CTIP_DEMO_MODE` | `true`/`false` — auto-fill sparse results with synthetic demo data (default `true`) |
| `CTIP_FEED_REFRESH_MINUTES` | How often to re-poll IOC feeds (default `10`) |
| `CTIP_OTX_API_KEY` | Free key to enable the optional AlienVault OTX feed |
| `CTIP_NVD_API_KEY` | Free key for higher NVD API rate limits |
| `CTIP_ABUSECH_AUTH_KEY` | Free key (register at [auth.abuse.ch](https://auth.abuse.ch/)) — required to enable the ThreatFox and MalwareBazaar feeds |
| `CTIP_MAPTILER_API_KEY` | Free key (sign up at [cloud.maptiler.com](https://cloud.maptiler.com), 100k tile loads/month, no card) — gives the threat map a proper dark cartographic style instead of the plain-OSM CSS-filter fallback |
| `CTIP_SLACK_WEBHOOK_URL` | Slack incoming webhook for critical-severity alerts |
| `CTIP_SMTP_*` / `CTIP_ALERT_EMAIL_TO` | Email alerting |
| `CTIP_ALERT_SEVERITY_THRESHOLD` | Score (0–100) above which an alert fires (default `85`) |
| `CTIP_CORS_ORIGINS` | Comma-separated origins allowed to call the API from another site |

## Embedding on your own website

The dashboard is a single static page with no build dependencies, so you can either:

1. **Iframe it:** point an `<iframe src="https://your-ctip-host/">` at wherever you deploy the backend, or
2. **Point it at a remote API:** copy `frontend/` onto your own site's static hosting and set `window.CTIP_API_BASE = "https://your-ctip-api-host"` before `js/app.js` loads, then make sure `CTIP_CORS_ORIGINS` on the backend includes your site's domain.

## Running the tests

The severity-scoring engine and MITRE ATT&CK mapping are pure functions with no external dependencies, so they're fully unit tested and safe to run anywhere:

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Design notes / things worth knowing

- **Severity scoring** (`app/services/enrichment.py`) is a transparent weighted formula — not a black box — combining threat-type base severity, feed-reported confidence, recency (exponential decay), and corroboration volume. See the docstring and tests for the exact weights.
- **MITRE ATT&CK mapping** (`app/services/mitre_map.py`) is a curated keyword lookup table rather than an ML classifier — deliberately, so it's transparent, fast, and testable offline. It's a good place to extend with more techniques or a smarter classifier later.
- **Demo mode** exists so this is honest and useful as a portfolio piece: anyone cloning the repo sees a fully working, populated dashboard immediately, and every synthetic record is labeled `is_synthetic: true` / shown with a "demo" tag in the UI — it's never presented as real intelligence.
- **Free feeds change.** abuse.ch, NVD, and CISA occasionally adjust field names or auth requirements on their public APIs. Every connector in `app/services/feeds/` parses defensively and logs (rather than crashes) on unexpected shapes, and the aggregator's demo-mode fallback means a single feed drifting doesn't take down the dashboard — but if you see a feed silently returning zero results, check that source's current API docs.

## Ideas for extending this further

- Swap SQLite for Postgres + add a `docker-compose` Postgres service for a production deployment
- Add a graph database (Neo4j) to model relationships between IOCs, malware families, and campaigns
- Add user auth + saved watchlists/dashboards
- Add a proper ML classifier for threat-type/ATT&CK tagging instead of the keyword heuristic
- Add STIX/TAXII export for interoperability with other threat-intel tooling
- Add historical replay / time-scrubber on the map

## License

MIT — see [LICENSE](LICENSE).
