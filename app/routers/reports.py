from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from ..database import get_db
from ..services.dam import record_event
from ..services.reports import generate_activity_csv, generate_activity_json, store_report_metadata

router = APIRouter(prefix="/reports", tags=["reports"])


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
        message=f"Activity report CSV generated",
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
        message=f"Activity report JSON generated",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        metadata={"report_id": report_id, "format": "json"},
    )

    return {"report_id": report_id, "file_path": file_path, "format": "json"}
