from __future__ import annotations

from fastapi import APIRouter, Request

from ..config import get_settings
from ..utils.response import success_response

router = APIRouter(tags=["system"])


@router.get("/system/smtp-status")
def smtp_status():
    settings = get_settings()
    return success_response({
        "smtp_enabled": settings.smtp_enabled,
        "smtp_host": settings.smtp_host or None,
        "smtp_port": settings.smtp_port,
        "smtp_user": settings.smtp_user or None,
        "smtp_sender": settings.smtp_sender or None,
        "smtp_starttls": settings.smtp_starttls,
        "admin_alert_emails": list(settings.admin_alert_emails),
    })


@router.post("/system/smtp-test")
def smtp_test():
    return success_response({"message": "SMTP test is not configured for local mode."})
