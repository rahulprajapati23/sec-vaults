"""Reports API — summary stats, on-demand email delivery, CSV/JSON export."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from ..database import get_db
from ..services.audit import get_logger
from ..services.reports import (
    generate_activity_csv,
    generate_activity_json,
    store_report_metadata,
    get_report_summary_api,
    send_daily_report,
    send_weekly_report,
)

router = APIRouter(prefix="/reports", tags=["reports"])
logger = get_logger()


# ─── Summary (no email) ───────────────────────────────────────────────────────

@router.get("/summary")
def report_summary(
    request: Request,
    days: int = Query(default=1, ge=1, le=90, description="Look-back window in days"),
):
    """
    Return security statistics for the past N days.
    Used by the dashboard Logs & Reports page.
    """
    from ..main import require_current_user
    require_current_user(request)

    try:
        return get_report_summary_api(days)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ─── On-demand email reports ──────────────────────────────────────────────────

@router.post("/send/daily")
def trigger_daily_report(request: Request):
    """Manually trigger the daily security report email."""
    from ..main import require_admin_user
    user = require_admin_user(request)

    # Run in background thread so HTTP response returns immediately
    def _send():
        try:
            result = send_daily_report()
            logger.info(
                "daily_report_triggered_manually sent=%s events=%d user=%s",
                result.get("sent"), result.get("events_count", 0), user["email"],
            )
        except Exception as exc:
            logger.error("daily_report_failed error=%s", exc)

    threading.Thread(target=_send, daemon=True).start()
    return {"status": "queued", "message": "Daily report is being generated and emailed to admin recipients."}



@router.post("/send/weekly")
def trigger_weekly_report(request: Request):
    """Manually trigger the weekly security report email."""
    from ..main import require_admin_user
    user = require_admin_user(request)

    def _send():
        try:
            result = send_weekly_report()
            logger.info(
                "weekly_report_triggered_manually sent=%s events=%d user=%s",
                result.get("sent"), result.get("events_count", 0), user["email"],
            )
        except Exception as exc:
            logger.error("weekly_report_failed error=%s", exc)

    threading.Thread(target=_send, daemon=True).start()
    return {"status": "queued", "message": "Weekly report is being generated and emailed to admin recipients."}



# ─── File exports ─────────────────────────────────────────────────────────────

@router.post("/activity/csv")
def generate_activity_report_csv(
    request: Request,
    start_date: str = Query(...),
    end_date: str = Query(...),
    user_id: int | None = Query(None),
):
    from ..main import require_current_user
    user = require_current_user(request)
    if user_id and user_id != user["id"] and user["role"] not in {"admin", "auditor"}:
        raise HTTPException(status_code=403, detail="Cannot generate reports for other users")

    report_user_id = user_id or user["id"]
    with get_db() as conn:
        file_path = generate_activity_csv(conn, report_user_id, start_date, end_date)
        report_id = store_report_metadata(conn, report_user_id, "activity", "csv", file_path)

    record_event(
        event_type="report",
        severity="low",
        action="report_generated",
        status="success",
        message="Activity report CSV generated",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        metadata={"report_id": report_id, "format": "csv"},
    )
    return {"report_id": report_id, "file_path": file_path, "format": "csv"}


@router.post("/activity/json")
def generate_activity_report_json(
    request: Request,
    start_date: str = Query(...),
    end_date: str = Query(...),
    user_id: int | None = Query(None),
):
    from ..main import require_current_user
    user = require_current_user(request)
    if user_id and user_id != user["id"] and user["role"] not in {"admin", "auditor"}:
        raise HTTPException(status_code=403, detail="Cannot generate reports for other users")

    report_user_id = user_id or user["id"]
    with get_db() as conn:
        file_path = generate_activity_json(conn, report_user_id, start_date, end_date)
        report_id = store_report_metadata(conn, report_user_id, "activity", "json", file_path)

    record_event(
        event_type="report",
        severity="low",
        action="report_generated",
        status="success",
        message="Activity report JSON generated",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        metadata={"report_id": report_id, "format": "json"},
    )
    return {"report_id": report_id, "file_path": file_path, "format": "json"}
