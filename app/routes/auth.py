from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from datetime import datetime, timedelta, timezone
import json as _json
import hashlib

from ..config import get_settings
from ..database import get_db
from ..schemas import LoginRequest, RegisterRequest, UserOut
from ..security import create_access_token, hash_password, verify_password
from ..services.audit import get_logger
from ..services.dam import record_event
from ..services.notifications import send_email
from ..services.verification import create_email_verification_token, verify_email_token
from ..services.files import create_user, get_user_by_email
from ..services.intrusion import (
    IDENTITY_EMAIL,
    IDENTITY_IP,
    is_identity_blocked,
    is_login_rate_limited,
    register_failed_auth,
    register_login_attempt,
    reset_identity_failures,
)
from ..deps import require_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger()

def _cookie_samesite() -> str:
    value = get_settings().cookie_samesite
    if value in {"lax", "strict", "none"}:
        return value
    return "lax"

@router.post("/api-login")
def api_login(request: Request, email: str = Form(...), password: str = Form(...)):
    """JSON-compatible login endpoint for the React SPA."""
    payload = LoginRequest(email=email, password=password)
    source_ip = request.client.host if request.client else None

    with get_db() as conn:
        rate_limited, _ = is_login_rate_limited(conn, source_ip)
        if rate_limited:
            register_login_attempt(conn, identity_value=source_ip, email=payload.email, ip_address=source_ip, success=False, reason="rate_limited", severity="high")
            record_event(event_type="auth", severity="high", action="rate_limit", status="blocked", message="Login rate limit exceeded", actor_user_id=None, actor_email=payload.email, request=request)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts. Please try again soon.")

        email_blocked, email_reason = is_identity_blocked(conn, IDENTITY_EMAIL, payload.email.lower())
        ip_blocked, ip_reason = is_identity_blocked(conn, IDENTITY_IP, source_ip or "unknown")
        if email_blocked or ip_blocked:
            register_login_attempt(conn, identity_value=payload.email.lower(), email=payload.email, ip_address=source_ip, success=False, reason=email_reason or ip_reason, severity="critical")
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account or IP is blocked due to too many failed attempts.")

        user = get_user_by_email(conn, payload.email)
        if not user or not verify_password(payload.password, user["password_hash"]):
            register_failed_auth(conn, IDENTITY_EMAIL, payload.email.lower())
            register_failed_auth(conn, IDENTITY_IP, source_ip or "unknown")
            register_login_attempt(conn, identity_value=payload.email.lower(), email=payload.email, ip_address=source_ip, success=False, reason="invalid_credentials", severity="medium")
            record_event(event_type="auth", severity="medium", action="login", status="failed", message="Invalid credentials", actor_user_id=None, actor_email=payload.email, request=request)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

        reset_identity_failures(conn, IDENTITY_EMAIL, payload.email.lower())
        reset_identity_failures(conn, IDENTITY_IP, source_ip or "unknown")
        register_login_attempt(conn, identity_value=payload.email.lower(), email=payload.email, ip_address=source_ip, success=True, reason="ok", severity="low")

    token = create_access_token(str(user["id"]))
    record_event(event_type="auth", severity="low", action="login", status="success", message="User logged in via API", actor_user_id=user["id"], actor_email=user["email"], request=request)

    response = JSONResponse(content={"id": user["id"], "email": user["email"], "role": user["role"]})
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite=_cookie_samesite(),
        secure=get_settings().cookie_secure,
        max_age=60 * 60 * 24,
    )
    return response

@router.post("/register")
def register(request: Request):
    return RedirectResponse(url="/auth/register-form", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    payload = LoginRequest(email=email, password=password)
    source_ip = request.client.host if request.client else None
    
    with get_db() as conn:
        rate_limited, _ = is_login_rate_limited(conn, source_ip)
        if rate_limited:
            register_login_attempt(conn, identity_value=source_ip, email=payload.email, ip_address=source_ip, success=False, reason="rate_limited", severity="high")
            record_event(event_type="auth", severity="high", action="rate_limit", status="blocked", message="Login rate limit exceeded", actor_user_id=None, actor_email=payload.email, request=request)
            return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Too many login attempts."}, status_code=status.HTTP_429_TOO_MANY_REQUESTS)

        user = get_user_by_email(conn, payload.email)
        if not user or not verify_password(payload.password, user["password_hash"]):
            register_failed_auth(conn, IDENTITY_EMAIL, payload.email.lower())
            return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=status.HTTP_401_UNAUTHORIZED)

    token = create_access_token(str(user["id"]))
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie("access_token", token, httponly=True, samesite=_cookie_samesite(), secure=get_settings().cookie_secure, max_age=60 * 60 * 24)
    return response

@router.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response

@router.post("/api-logout")
def api_logout():
    response = JSONResponse(content={"ok": True, "message": "Logged out successfully"})
    response.delete_cookie("access_token", samesite="lax")
    return response

@router.get("/me", response_model=UserOut)
def me(request: Request):
    user = require_current_user(request)
    return UserOut(id=user["id"], email=user["email"], created_at=user["created_at"], role=user["role"])
