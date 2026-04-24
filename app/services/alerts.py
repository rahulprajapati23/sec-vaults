from __future__ import annotations

import smtplib
from email.message import EmailMessage

from ..config import get_settings
from .audit import get_logger

logger = get_logger()


def send_security_alert(*, subject: str, body: str, recipients: list[str]) -> None:
    settings = get_settings()
    if not settings.smtp_enabled:
        return
    if not recipients:
        return
    if not settings.smtp_host or not settings.smtp_sender:
        logger.warning("smtp_not_configured recipients=%s", len(recipients))
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_sender
    message["To"] = ", ".join(sorted(set(recipients)))
    message.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_starttls:
                server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(message)
    except Exception as exc:
        logger.exception("smtp_alert_failed error=%s", exc)
