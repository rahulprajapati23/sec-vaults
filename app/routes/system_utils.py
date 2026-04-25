from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from ..config import get_settings
from ..services.notifications import send_email
from ..services.dam import record_event
from ..deps import require_current_user

router = APIRouter(prefix="/system", tags=["system"])

@router.get("/smtp-status")
def smtp_status(request: Request):
    require_current_user(request)
    settings = get_settings()
    return {
        "smtp_enabled": settings.smtp_enabled,
        "smtp_host": settings.smtp_host or None,
        "smtp_port": settings.smtp_port,
        "smtp_user": settings.smtp_user[:3] + "***" if settings.smtp_user else None,
        "smtp_sender": settings.smtp_sender or None,
        "smtp_starttls": settings.smtp_starttls,
        "admin_alert_emails": list(settings.admin_alert_emails),
    }

@router.post("/smtp-test")
def smtp_test(request: Request):
    user = require_current_user(request)
    settings = get_settings()

    if not settings.smtp_enabled:
        return JSONResponse(status_code=400, content={"success": False, "error": "SMTP is disabled."})
    if not settings.smtp_host:
        return JSONResponse(status_code=400, content={"success": False, "error": "SMTP_HOST is not configured."})

    recipient = user["email"]
    ok = send_email(
        subject="✅ SecureVault SMTP Test",
        body="This is a test email from SecureVault.",
        recipients=[recipient],
    )
    
    record_event(
        event_type="system", severity="low", action="smtp_test",
        status="success" if ok else "failed", message="SMTP test email sent",
        actor_user_id=user["id"], actor_email=user["email"], request=request,
    )

    if ok:
        return {"success": True, "message": f"Test email sent to {recipient}"}
    return JSONResponse(status_code=500, content={"success": False, "error": "SMTP send failed."})
