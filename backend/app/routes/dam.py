from __future__ import annotations

from fastapi import APIRouter, Request

from ..database import get_db
from ..deps import require_current_user, require_admin_user
from ..utils.response import success_response

router = APIRouter(tags=["dam"])


@router.get("/dam/events")
def dam_events(request: Request, limit: int = 100):
    user = require_current_user(request)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM dam_events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return success_response({"events": [dict(row) for row in rows]})
