from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..database import get_db
from ..services.analytics import get_dashboard_stats, get_user_activity_summary

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/dashboard")
def get_dashboard(request: Request):
    from ..main import require_admin_user

    require_admin_user(request)
    with get_db() as conn:
        stats = get_dashboard_stats(conn)

    return stats


@router.get("/user/{user_id}")
def get_user_analytics(user_id: int, request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    if user["id"] != user_id and user["role"] not in {"admin", "auditor"}:
        raise HTTPException(status_code=403, detail="Cannot view other user's analytics")

    with get_db() as conn:
        summary = get_user_activity_summary(conn, user_id)

    return summary


@router.get("/me")
def get_my_analytics(request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        summary = get_user_activity_summary(conn, user["id"])

    return summary
