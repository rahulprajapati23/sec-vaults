from __future__ import annotations

import smtplib
from email.message import EmailMessage

import httpx

from ..config import get_settings
from .audit import get_logger

logger = get_logger()


def send_email(*, subject: str, body: str, html_body: str | None = None, recipients: list[str]) -> bool:
    settings = get_settings()
    if not recipients:
        return False
    if not settings.smtp_enabled or not settings.smtp_host or not settings.smtp_sender:
        logger.warning("smtp_not_configured recipients=%s", len(recipients))
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_sender
    message["To"] = ", ".join(sorted(set(recipients)))
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_starttls:
                server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(message)
            return True
    except Exception as exc:
        logger.exception("smtp_alert_failed error=%s", exc)
        return False


def send_telegram_alert(*, subject: str, body: str) -> bool:
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token or not settings.telegram_chat_ids:
        return False

    message_text = f"*{subject}*\n\n{body}"
    for chat_id in settings.telegram_chat_ids:
        try:
            url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            with httpx.Client(timeout=5.0) as client:
                response = client.post(
                    url,
                    json={"chat_id": chat_id, "text": message_text, "parse_mode": "Markdown"},
                )
                response.raise_for_status()
        except Exception as exc:
            logger.warning("telegram_alert_failed chat_id=%s error=%s", chat_id, exc)
    return True


def send_security_alert(
    *,
    subject: str,
    body: str,
    recipients: list[str],
    include_telegram: bool = True,
) -> None:
    settings = get_settings()
    recipients = [email for email in recipients if email]
    admin_recipients = list(recipients) + list(settings.admin_alert_emails)
    admin_recipients = sorted(set(admin_recipients))

    send_email(subject=subject, body=body, recipients=admin_recipients)
    if include_telegram:
        send_telegram_alert(subject=subject, body=body)
