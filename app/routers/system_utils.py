"""System utility endpoints — SMTP test, health, config status."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import get_settings
from ..services.notifications import send_email
from ..services.dam import record_event

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/smtp-status")
def smtp_status(request: Request):
    """Return current SMTP configuration status (no credentials exposed)."""
    from ..deps import require_current_user
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
    """Send a test email to verify SMTP is working correctly."""
    from ..deps import require_current_user
    user = require_current_user(request)
    settings = get_settings()

    if not settings.smtp_enabled:
        return JSONResponse(status_code=400, content={
            "success": False,
            "error": "SMTP is disabled. Set SMTP_ENABLED=true in your .env file."
        })
    if not settings.smtp_host:
        return JSONResponse(status_code=400, content={
            "success": False,
            "error": "SMTP_HOST is not configured in .env"
        })

    recipient = user["email"]
    ok = send_email(
        subject="✅ SecureVault SMTP Test",
        body=f"""Hello,

This is a test email from your SecureVault system to confirm SMTP is working correctly.

Configuration:
  Host:   {settings.smtp_host}:{settings.smtp_port}
  Sender: {settings.smtp_sender}
  TLS:    {"Yes (STARTTLS)" if settings.smtp_starttls else "No"}

If you received this email, your SMTP setup is working perfectly.

— SecureVault Security System
""",
        html_body=f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:32px;border-radius:12px">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
    <div style="width:40px;height:40px;background:#2563eb;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px">🛡️</div>
    <span style="font-size:20px;font-weight:700;color:#ffffff">SecureVault</span>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:20px">
    <p style="color:#4ade80;font-size:16px;font-weight:700;margin:0 0 8px">✅ SMTP Test Successful</p>
    <p style="color:#94a3b8;font-size:13px;margin:0">Your email notification system is configured and working correctly.</p>
  </div>
  <table style="width:100%;border-collapse:collapse">
    <tr><td style="padding:6px 0;color:#64748b;font-size:12px">SMTP Host</td><td style="color:#e2e8f0;font-size:12px;font-family:monospace">{settings.smtp_host}:{settings.smtp_port}</td></tr>
    <tr><td style="padding:6px 0;color:#64748b;font-size:12px">Sender</td><td style="color:#e2e8f0;font-size:12px;font-family:monospace">{settings.smtp_sender}</td></tr>
    <tr><td style="padding:6px 0;color:#64748b;font-size:12px">TLS</td><td style="color:#e2e8f0;font-size:12px">{"STARTTLS enabled" if settings.smtp_starttls else "Disabled"}</td></tr>
  </table>
  <p style="color:#475569;font-size:11px;margin-top:24px;border-top:1px solid #1e293b;padding-top:12px">
    This email was triggered by a manual test from the SecureVault Settings page.<br>
    If you did not initiate this, contact your system administrator.
  </p>
</div>
""",
        recipients=[recipient],
    )

    record_event(
        event_type="system",
        severity="low",
        action="smtp_test",
        status="success" if ok else "failed",
        message=f"SMTP test email {'sent' if ok else 'failed'} to {recipient}",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    if ok:
        return {"success": True, "message": f"Test email sent to {recipient}"}
    return JSONResponse(status_code=500, content={
        "success": False,
        "error": "SMTP send failed. Check server logs for details (smtp_alert_failed)."
    })

