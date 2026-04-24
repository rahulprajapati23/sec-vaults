"""Email OTP registration and authentication flow."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse

from ..config import get_settings
from ..database import get_db
from ..services.notifications import send_email
from ..services.files import create_user as create_user_db, get_user_by_email as get_user_by_email_db
from ..security import hash_password
from ..services.dam import record_event


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()

router = APIRouter(prefix="/auth", tags=["auth-otp"])


@router.post("/email-otp-register")
def request_otp_register(request: Request, email: str = Form(...)):
    """Step 1: User enters email, receive OTP via email."""
    email = email.strip().lower()

    # Check if email already exists (in SQLite)
    with get_db() as conn:
        existing_user = get_user_by_email_db(conn, email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
            )

    # Generate 6-digit OTP
    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    otp_hash = _hash_otp(otp)
    otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Store hashed OTP in database (never store plaintext)
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO otp_tokens (email, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                email,
                otp_hash,
                otp_expires_at.isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()

    # Send OTP via email
    settings = get_settings()
    if settings.smtp_enabled:
        send_email(
            subject="Your Email Verification OTP",
            body=f"""
Welcome to Secure Data Storage!

Your One-Time Password (OTP) is: {otp}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.
            """,
            recipients=[email],
        )
    else:
        # Dev mode: log OTP to console
        import logging
        logging.warning(f"[DEV MODE] OTP for {email}: {otp}")

    # Redirect to OTP verification form
    return request.app.state.templates.TemplateResponse(
        "verify_otp.html",
        {"request": request, "email": email, "message": "Verification code sent to your email"}
    )


@router.post("/verify-otp-register")
def verify_otp_register(request: Request, email: str = Form(...), otp: str = Form(...), password: str = Form(...)):
    """Step 2: User verifies OTP and sets password."""
    email = email.strip().lower()
    otp = otp.strip()

    # Validate OTP format
    if not otp.isdigit() or len(otp) != 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP format"
        )

    # Verify OTP from database
    otp_hash = _hash_otp(otp)
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT * FROM otp_tokens
            WHERE email = ? AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (email, datetime.now(timezone.utc).isoformat()),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OTP",
            )

        # Timing-safe comparison against stored hash (prevents timing attacks)
        if not hmac.compare_digest(row["token_hash"], otp_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP",
            )

        # Delete used OTP (single-use)
        conn.execute("DELETE FROM otp_tokens WHERE email = ?", (email,))
        conn.commit()

    # Validate password strength
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )

    # Create user in SQLite database
    try:
        with get_db() as conn:
            user = create_user_db(conn, email, hash_password(password), role="user")
            user_id = user["id"]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User creation failed: {str(e)}",
        )

    # Log registration event via DAM pipeline (maintains hash-chain integrity)
    record_event(
        event_type="auth",
        severity="low",
        action="register_otp",
        status="success",
        message="User registered via OTP email verification",
        actor_user_id=user_id,
        actor_email=email,
        request=request,
    )

    # Return success page
    return HTMLResponse(
        """
        <html>
        <head>
            <title>Registration Successful</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .success { color: green; font-size: 20px; }
                a { color: blue; text-decoration: none; }
            </style>
        </head>
        <body>
            <h1 class="success">✓ Registration Successful!</h1>
            <p>Your email has been verified and account created.</p>
            <p><a href="/auth/login">Login to your account</a></p>
        </body>
        </html>
        """
    )


@router.get("/register-form")
def register_form(request: Request):
    """Render registration form with OTP flow."""
    return request.app.state.templates.TemplateResponse(
        "register_otp.html",
        {"request": request},
    )


@router.get("/verify-otp-form")
def verify_otp_form(request: Request, email: str = None):
    """Render OTP verification form."""
    return request.app.state.templates.TemplateResponse(
        "verify_otp.html",
        {"request": request, "email": email or ""},
    )
