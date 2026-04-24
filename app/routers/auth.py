from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta, timezone

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

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger()


@router.post("/api-login")
def api_login(request: Request, email: str = Form(...), password: str = Form(...)):
    """JSON-compatible login endpoint for the React SPA.
    Returns a JSON response with user info and sets the HttpOnly cookie.
    """
    from fastapi.responses import JSONResponse
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
    response.set_cookie("access_token", token, httponly=True, samesite="lax", secure=False, max_age=60 * 60 * 24)
    return response



@router.post("/register")
def register(request: Request):
    """Redirect old registration endpoint to new OTP-based flow."""
    return RedirectResponse(url="/auth/register-form", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    payload = LoginRequest(email=email, password=password)
    source_ip = request.client.host if request.client else None
    response = None
    events: list[dict] = []
    user = None

    with get_db() as conn:
        rate_limited, _ = is_login_rate_limited(conn, source_ip)
        if rate_limited:
            register_login_attempt(
                conn,
                identity_value=source_ip,
                email=payload.email,
                ip_address=source_ip,
                success=False,
                reason="rate_limited",
                severity="high",
            )
            events.append(
                {
                    "event_type": "auth",
                    "severity": "high",
                    "action": "rate_limit",
                    "status": "blocked",
                    "message": "Login rate limit exceeded",
                    "actor_user_id": None,
                    "actor_email": payload.email,
                    "request": request,
                }
            )
            response = request.app.state.templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Too many login attempts. Please try again soon."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        else:
            email_blocked, email_reason = is_identity_blocked(conn, IDENTITY_EMAIL, payload.email.lower())
            ip_blocked, ip_reason = is_identity_blocked(conn, IDENTITY_IP, source_ip or "unknown")
            if email_blocked or ip_blocked:
                reason = email_reason if email_blocked else ip_reason
                register_login_attempt(
                    conn,
                    identity_value=payload.email.lower(),
                    email=payload.email,
                    ip_address=source_ip,
                    success=False,
                    reason=reason,
                    severity="critical" if reason == "permanent_block" else "high",
                )
                events.append(
                    {
                        "event_type": "intrusion",
                        "severity": "critical" if reason == "permanent_block" else "high",
                        "action": "brute_force_detected",
                        "status": "blocked",
                        "message": f"Login blocked due to {reason}",
                        "actor_user_id": None,
                        "actor_email": payload.email,
                        "request": request,
                    }
                )
                response = request.app.state.templates.TemplateResponse(
                    "login.html",
                    {"request": request, "error": "Account or IP is temporarily/permanently blocked."},
                    status_code=status.HTTP_423_LOCKED,
                )
            else:
                user = get_user_by_email(conn, payload.email)
                if not user or not verify_password(payload.password, user["password_hash"]):
                    register_login_attempt(
                        conn,
                        identity_value=payload.email.lower(),
                        email=payload.email,
                        ip_address=source_ip,
                        success=False,
                        reason="invalid_credentials",
                        severity="medium",
                    )
                    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=get_settings().login_failure_window_minutes)).isoformat()
                    recent_failed = conn.execute(
                        """
                        SELECT COUNT(*) AS total
                        FROM login_attempt_logs
                        WHERE (email = ? OR ip_address = ?)
                          AND success = 0
                          AND created_at >= ?
                        """,
                        (payload.email, source_ip, cutoff),
                    ).fetchone()
                    blocked_email, reason_email = register_failed_auth(conn, IDENTITY_EMAIL, payload.email.lower())
                    blocked_ip, reason_ip = register_failed_auth(conn, IDENTITY_IP, source_ip or "unknown")
                    brute_force_detected = (recent_failed["total"] if recent_failed else 0) >= get_settings().brute_force_threshold
                    logger.warning("failed_login email=%s", payload.email)
                    events.append(
                        {
                            "event_type": "auth",
                            "severity": "high" if (blocked_email or blocked_ip or brute_force_detected) else "medium",
                            "action": "login",
                            "status": "failed",
                            "message": "Invalid credentials",
                            "actor_user_id": user["id"] if user else None,
                            "actor_email": payload.email,
                            "request": request,
                            "metadata": {
                                "email_block_reason": reason_email,
                                "ip_block_reason": reason_ip,
                                "blocked": blocked_email or blocked_ip,
                                "recent_failed_5m": recent_failed["total"] if recent_failed else 0,
                            },
                        }
                    )
                    if brute_force_detected:
                        events.append(
                            {
                                "event_type": "intrusion",
                                "severity": "high",
                                "action": "brute_force_detected",
                                "status": "blocked",
                                "message": "Brute-force threshold reached",
                                "actor_user_id": user["id"] if user else None,
                                "actor_email": payload.email,
                                "request": request,
                                "metadata": {
                                    "failed_attempts_5m": recent_failed["total"] if recent_failed else 0,
                                    "threshold": get_settings().brute_force_threshold,
                                    "window_minutes": get_settings().login_failure_window_minutes,
                                },
                            }
                        )
                        response = request.app.state.templates.TemplateResponse(
                            "login.html",
                            {"request": request, "error": "Too many failed login attempts. Try later."},
                            status_code=status.HTTP_423_LOCKED,
                        )
                    else:
                        response = request.app.state.templates.TemplateResponse(
                            "login.html",
                            {"request": request, "error": "Invalid credentials"},
                            status_code=status.HTTP_401_UNAUTHORIZED,
                        )
                else:
                    reset_identity_failures(conn, IDENTITY_EMAIL, payload.email.lower())
                    reset_identity_failures(conn, IDENTITY_IP, source_ip or "unknown")
                    register_login_attempt(
                        conn,
                        identity_value=payload.email.lower(),
                        email=payload.email,
                        ip_address=source_ip,
                        success=True,
                        reason="ok",
                        severity="low",
                    )

    for event in events:
        record_event(**event)
    if response is not None:
        return response

    logger.info("login email=%s", payload.email)
    record_event(
        event_type="auth",
        severity="low",
        action="login",
        status="success",
        message="User logged in",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )
    token = create_access_token(str(user["id"]))
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie("access_token", token, httponly=True, samesite="lax", secure=False, max_age=60 * 60 * 24)
    return response


@router.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response


@router.post("/api-logout")
def api_logout():
    """JSON-returning logout for the React SPA — clears the HttpOnly cookie."""
    from fastapi.responses import JSONResponse
    response = JSONResponse(content={"ok": True, "message": "Logged out successfully"})
    response.delete_cookie("access_token", samesite="lax")
    return response


@router.post("/request-password-reset")
def request_password_reset(request: Request):
    """
    Initiate password reset: validate email, send OTP via email.
    Always returns success to prevent user enumeration.
    """
    from fastapi.responses import JSONResponse
    import json as _json

    try:
        body = _json.loads(request._body if hasattr(request, '_body') else b'{}')
        email = body.get("email", "").strip().lower()
    except Exception:
        email = ""

    if not email:
        # Read from form data fallback
        return JSONResponse(content={"ok": True, "message": "If that email exists, a reset code was sent."})

    with get_db() as conn:
        user = get_user_by_email(conn, email)

    if user and user["is_active"]:
        # Re-use the OTP system for password reset
        from ..services.verification import create_email_verification_token
        token, token_hash = create_email_verification_token(
            __import__('sqlite3').connect(str(get_settings().database_path)),
            user["id"], email
        )
        reset_link = f"http://localhost:5173/reset-password?token={token}&email={email}"
        send_email(
            subject="🔐 SecureVault Password Reset",
            body=f"""You requested a password reset for SecureVault.

Reset link (valid 15 minutes):
{reset_link}

If you did not request this, ignore this email.
""",
            html_body=f"""
<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:32px;border-radius:12px">
  <div style="margin-bottom:24px">
    <span style="font-size:20px;font-weight:700;color:#ffffff">🛡️ SecureVault</span>
  </div>
  <h2 style="color:#ffffff;font-size:18px;margin:0 0 12px">Password Reset Request</h2>
  <p style="color:#94a3b8;font-size:14px">Click the button below to reset your password. This link expires in <strong style="color:#e2e8f0">15 minutes</strong>.</p>
  <a href="{reset_link}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px">Reset My Password</a>
  <p style="color:#475569;font-size:12px;margin-top:24px">If you didn't request this, you can safely ignore this email.</p>
</div>""",
            recipients=[email],
        )
        record_event(
            event_type="auth", severity="low", action="password_reset_request",
            status="success", message="Password reset email sent",
            actor_user_id=user["id"], actor_email=email, request=request,
        )

    # Always return success (prevents user enumeration)
    return JSONResponse(content={"ok": True, "message": "If that email exists, a reset code was sent."})


@router.get("/me", response_model=UserOut)
def me(request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    return UserOut(id=user["id"], email=user["email"], created_at=user["created_at"], role=user["role"])


@router.post("/verify-email-request")
def request_email_verification(request: Request):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        token, token_hash = create_email_verification_token(conn, user["id"], user["email"])

    verify_url = f"http://127.0.0.1:8000/auth/verify-email?token={token}"
    send_email(
        subject="Verify Your Email",
        body=f"Click the link to verify your email:\n{verify_url}\n\nValid for 24 hours.",
        recipients=[user["email"]],
    )

    record_event(
        event_type="auth",
        severity="low",
        action="email_verify_request",
        status="success",
        message="Email verification requested",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return {"message": "Verification email sent"}


@router.get("/verify-email")
def verify_email(request: Request, token: str = None):
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token required")

    from ..main import require_current_user

    try:
        user = require_current_user(request)
    except HTTPException:
        return request.app.state.templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Please login first"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    import hashlib

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as conn:
        verified = verify_email_token(conn, user["id"], token_hash)

    if not verified:
        record_event(
            event_type="auth",
            severity="medium",
            action="email_verify",
            status="failed",
            message="Invalid or expired email verification token",
            actor_user_id=user["id"],
            actor_email=user["email"],
            request=request,
        )
        return request.app.state.templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid or expired token"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    record_event(
        event_type="auth",
        severity="low",
        action="email_verify",
        status="success",
        message="Email verified",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return request.app.state.templates.TemplateResponse(
        "login.html",
        {"request": request, "success": "Email verified successfully"},
    )
