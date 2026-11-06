from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import scheduler
from app.config import settings
from app.database import init_db
from app.routers import campaigns, config as config_router
from app.routers import cve, export, map as map_router, mitre, search, stats, threats, ws
from app.services import aggregator
from app.utils.logger import get_logger

logger = get_logger("ctip.main")

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


def _run_initial_ingestion(loop: asyncio.AbstractEventLoop) -> None:
    """Runs the first feed pull in a background thread so API/UI startup
    isn't blocked on network calls to external threat feeds."""

    def _job():
        logger.info("running initial threat + CVE ingestion...")
        try:
            changed = aggregator.refresh_threat_events()
            aggregator.broadcast_new_events(changed, loop)
        except Exception:  # noqa: BLE001
            logger.exception("initial threat ingestion failed")
        try:
            aggregator.refresh_cves()
        except Exception:  # noqa: BLE001
            logger.exception("initial CVE ingestion failed")
        logger.info("initial ingestion complete")

    threading.Thread(target=_job, daemon=True).start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting %s (env=%s, demo_mode=%s)", settings.APP_NAME, settings.ENV, settings.DEMO_MODE)
    init_db()
    loop = asyncio.get_running_loop()
    _run_initial_ingestion(loop)
    scheduler.start(loop)
    yield
    scheduler.stop()
    logger.info("shutdown complete")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "A live cyber threat intelligence aggregation and visualization platform. "
        "Pulls real IOCs from URLhaus, ThreatFox, MalwareBazaar and CISA KEV/NVD, "
        "enriches them with GeoIP + severity scoring + MITRE ATT&CK mapping, and "
        "streams updates to connected dashboards in real time."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (threats.router, map_router.router, stats.router, cve.router, mitre.router, search.router, export.router, ws.router, config_router.router, campaigns.router):
    app.include_router(router)


@app.get("/api/health", tags=["health"])
def health():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "demo_mode": settings.DEMO_MODE,
    }


# Serve the static dashboard frontend (built with plain HTML/CSS/JS, no
# build step required) at the site root, so this same FastAPI process can
# power both the API and the embeddable dashboard.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
