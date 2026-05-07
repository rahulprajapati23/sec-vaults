from __future__ import annotations

from fastapi import APIRouter, Request

from ..database import get_db
from ..deps import require_current_user, require_admin_user
from ..services.dam import record_event
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


@router.post("/dam/record")
async def record_client_event(request: Request, body: dict):
    # Try to get user if authenticated, but don't force it for public events
    user = None
    try:
        user = require_current_user(request)
    except Exception:
        pass
    
    record_event(
        event_type=body.get("event_type", "client_interaction"),
        severity=body.get("severity", "low"),
        actor_user_id=user["id"] if user else None,
        actor_email=user["email"] if user else None,
        source_ip=request.client.host if request.client else "unknown",
        action=body.get("action", "unknown_action"),
        status=body.get("status", "success"),
        message=body.get("message", ""),
        metadata=body.get("metadata", {}),
    )
    return success_response({"message": "Event recorded"})
