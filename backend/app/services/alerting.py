"""
Sends notifications for high-severity threat events. Both channels are
optional and configured purely via environment variables (see .env.example);
with nothing configured, alerts are simply logged locally and recorded in
the AlertLog table so the dashboard's "Alert History" panel still has
something meaningful to show.
"""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText

import requests

from app.config import settings
from app.database import session_scope
from app.models import AlertLog
from app.utils.logger import get_logger

logger = get_logger("ctip.alerting")


def _record(message: str, severity: str, channel: str, success: bool) -> None:
    try:
        with session_scope() as db:
            db.add(AlertLog(message=message, severity=severity, channel=channel, success=success))
    except Exception as exc:  # noqa: BLE001
        logger.error("failed to record alert log entry: %s", exc)


def _send_slack(message: str) -> bool:
    if not settings.SLACK_WEBHOOK_URL:
        return False
    try:
        resp = requests.post(
            settings.SLACK_WEBHOOK_URL, json={"text": message}, timeout=settings.HTTP_TIMEOUT_SECONDS
        )
        return resp.status_code < 300
    except Exception as exc:  # noqa: BLE001
        logger.warning("slack alert failed: %s", exc)
        return False


def _send_email(subject: str, body: str) -> bool:
    if not (settings.SMTP_HOST and settings.ALERT_EMAIL_TO):
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_USER or "ctip@localhost"
        msg["To"] = settings.ALERT_EMAIL_TO

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.HTTP_TIMEOUT_SECONDS) as server:
            server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(msg["From"], [settings.ALERT_EMAIL_TO], msg.as_string())
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("email alert failed: %s", exc)
        return False


def alert_on_critical_event(event: dict) -> None:
    """Called by the aggregator for any newly-ingested event whose severity
    crosses ALERT_SEVERITY_THRESHOLD."""
    if event.get("severity_score", 0) < settings.ALERT_SEVERITY_THRESHOLD:
        return

    message = (
        f":rotating_light: CTIP Alert — {event.get('severity_label', 'high').upper()} threat detected\n"
        f"Indicator: {event.get('ioc_value')} ({event.get('ioc_type')})\n"
        f"Type: {event.get('threat_type')} | Family: {event.get('malware_family') or 'n/a'}\n"
        f"Source: {event.get('source_feed')} | Score: {event.get('severity_score')}/100\n"
        f"Country: {event.get('country') or 'unknown'}"
    )

    sent_anywhere = False
    if _send_slack(message):
        _record(message, event.get("severity_label", "high"), "slack", True)
        sent_anywhere = True

    if _send_email(f"CTIP Alert: {event.get('threat_type')} — {event.get('ioc_value')}", message):
        _record(message, event.get("severity_label", "high"), "email", True)
        sent_anywhere = True

    if not sent_anywhere:
        # No channel configured (or both failed) — still log it locally so
        # the alert history panel reflects that a critical event occurred.
        logger.info("ALERT (no channel configured): %s", message.replace("\n", " | "))
        _record(message, event.get("severity_label", "high"), "log", True)
