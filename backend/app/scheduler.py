from __future__ import annotations

import asyncio

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.services import aggregator
from app.utils.logger import get_logger

logger = get_logger("ctip.scheduler")

scheduler = BackgroundScheduler()


def _run_threat_refresh(loop: asyncio.AbstractEventLoop) -> None:
    try:
        changed = aggregator.refresh_threat_events()
        aggregator.broadcast_new_events(changed, loop)
        logger.info("threat refresh complete: %d events upserted", len(changed))
    except Exception:  # noqa: BLE001
        logger.exception("threat refresh job failed")


def _run_cve_refresh() -> None:
    try:
        changed = aggregator.refresh_cves()
        logger.info("CVE refresh complete: %d entries upserted", len(changed))
    except Exception:  # noqa: BLE001
        logger.exception("CVE refresh job failed")


def _run_prune() -> None:
    try:
        aggregator.prune_old_events()
    except Exception:  # noqa: BLE001
        logger.exception("event pruning job failed")


def start(loop: asyncio.AbstractEventLoop) -> None:
    # NOTE: we deliberately do NOT pass next_run_time here. Passing
    # next_run_time=None to APScheduler's add_job() doesn't mean "use the
    # default schedule" — it means "add this job paused", and it would then
    # never fire on its own. Leaving the parameter out lets APScheduler
    # compute the normal first-fire time (now + interval) for us. The very
    # first ingestion happens separately via main.py's startup task, so this
    # recurring job's first automatic run simply follows one interval later.
    scheduler.add_job(
        _run_threat_refresh,
        "interval",
        minutes=settings.FEED_REFRESH_MINUTES,
        args=[loop],
        id="threat_refresh",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        _run_cve_refresh,
        "interval",
        minutes=settings.CVE_REFRESH_MINUTES,
        id="cve_refresh",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        _run_prune,
        "interval",
        hours=24,
        id="event_prune",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info(
        "scheduler started (threats every %dm, CVEs every %dm)",
        settings.FEED_REFRESH_MINUTES, settings.CVE_REFRESH_MINUTES,
    )


def stop() -> None:
    scheduler.shutdown(wait=False)
