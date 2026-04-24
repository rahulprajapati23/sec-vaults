from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from ..database import get_db
from ..services.dam import record_event
from ..services.sessions import list_user_sessions, logout_all_sessions, logout_session

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("")
def get_sessions(request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        sessions = list_user_sessions(conn, user["id"])

    return {"sessions": sessions}


@router.post("/{session_id}/logout")
def logout_specific_session(session_id: str, request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        logout_session(conn, session_id)

    record_event(
        event_type="auth",
        severity="low",
        action="logout",
        status="success",
        message="Session terminated",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return {"message": "Session logged out"}


@router.post("/logout-all")
def logout_all_user_sessions(request: Request, except_current: bool = True):
    from ..main import require_current_user

    user = require_current_user(request)
    except_hash = request.cookies.get("session_token_hash") if except_current else None

    with get_db() as conn:
        count = logout_all_sessions(conn, user["id"], except_token_hash=except_hash)

    record_event(
        event_type="auth",
        severity="low",
        action="logout_all",
        status="success",
        message=f"All sessions terminated (count: {count})",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return {"message": f"Logged out {count} sessions"}
