from __future__ import annotations

import json
from fastapi import APIRouter, Request, HTTPException

from ..config import get_settings
from ..database import get_db
from ..deps import require_current_user
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


from ..services.email import test_email_connection

@router.post("/system/smtp-test")
def smtp_test():
    result = test_email_connection()
    return success_response(result)


@router.get("/system/settings")
def get_system_settings(request: Request):
    require_current_user(request)
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    
    settings_dict = {row["key"]: json.loads(row["value"]) for row in rows}
    return success_response(settings_dict)


@router.post("/system/settings")
def update_system_settings(request: Request, body: dict):
    user = require_admin_user(request)
    
    with get_db() as conn:
        for key, value in body.items():
            json_val = json.dumps(value)
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json_val)
            )
        conn.commit()
    
    return success_response({"message": "Settings updated successfully"})
