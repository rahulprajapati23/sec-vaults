from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request, status

from ..database import get_db
from ..services.dam import record_event
from ..services.notifications import send_email
from ..services.verification import create_mfa_token, hash_otp, verify_mfa_token

router = APIRouter(prefix="/mfa", tags=["mfa"])


@router.post("/request-otp")
def request_mfa_otp(request: Request, email: str = Form(...)):
    from ..deps import require_current_user

    user = require_current_user(request)
    if user["email"].lower() != email.lower():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Can only request OTP for own email")

    with get_db() as conn:
        otp, otp_hash = create_mfa_token(conn, user["id"], method="email")

    send_email(
        subject="Your 2FA OTP Code",
        body=f"Your one-time code is: {otp}\n\nValid for 5 minutes.",
        recipients=[email],
    )

    record_event(
        event_type="auth",
        severity="low",
        action="mfa_request",
        status="success",
        message="MFA OTP requested",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return {"message": "OTP sent to email"}


@router.post("/verify-otp")
def verify_mfa_otp(request: Request, otp: str = Form(...)):
    from ..deps import require_current_user

    user = require_current_user(request)
    otp_hash = hash_otp(otp)

    with get_db() as conn:
        verified = verify_mfa_token(conn, user["id"], otp_hash)

    if not verified:
        record_event(
            event_type="auth",
            severity="medium",
            action="mfa_verify",
            status="failed",
            message="Invalid or expired MFA OTP",
            actor_user_id=user["id"],
            actor_email=user["email"],
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP")

    record_event(
        event_type="auth",
        severity="low",
        action="mfa_verify",
        status="success",
        message="MFA verification successful",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
    )

    return {"message": "MFA verified"}

