from __future__ import annotations

from fastapi import APIRouter

from app.config import settings

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("/public")
def public_config():
    """
    Non-secret, client-safe configuration. MapTiler keys in particular are
    meant to be used directly in browser JS (they're restricted by domain
    in MapTiler's dashboard, the same way Google Maps keys work) — this is
    not a leak of a backend secret.
    """
    return {
        "maptiler_api_key": settings.MAPTILER_API_KEY,
        "map_style": "dataviz-dark",
    }
