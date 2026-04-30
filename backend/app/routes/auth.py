from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import get_db
from ..schemas import LoginRequest, UserOut
from ..security import create_access_token, verify_password
from ..services.audit import get_logger
from ..services.files import get_user_by_email
from ..services.email import send_otp_email, test_email_connection
from ..utils.response import success_response, error_response
from ..deps import require_current_user

import random
import time
from ..security import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger()

@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    """Enterprise-grade login with standard response format."""
    with get_db() as conn:
        user = get_user_by_email(conn, email)
        if not user or not verify_password(password, user["password_hash"]):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=error_response("Invalid email or password")
            )

    token = create_access_token(str(user["id"]))
    
    response_data = {
        "user": {"id": user["id"], "email": user["email"], "role": user["role"]},
        "access_token": token
    }
    
    response = JSONResponse(content=success_response(response_data))
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite=get_settings().cookie_samesite,
        max_age=60 * 60 * 24,
    )
    return response

@router.get("/me")
def me(request: Request):
    user = require_current_user(request)
    return success_response({
        "id": user["id"],
        "email": user["email"],
        "role": user["role"]
    })

@router.post("/logout")
def logout():
    response = JSONResponse(content=success_response({"message": "Logged out"}))
    response.delete_cookie("access_token")
    return response

# --- Registration Logic ---
OTP_STORE = {}

@router.post("/email-otp-register")
def request_otp(email: str = Form(...)):
    """
    Request OTP for email-based registration.
    Sends OTP via SendGrid (works on Render free tier).
    Falls back to logging if email service unavailable.
    """
    email = email.lower().strip()
    with get_db() as conn:
        user = get_user_by_email(conn, email)
        if user:
            raise HTTPException(status_code=400, detail="Email already registered")
            
    otp = str(random.randint(100000, 999999))
    OTP_STORE[email] = {
        "otp": otp,
        "expires": time.time() + 300  # 5 minutes
    }
    
    # Attempt to send email
    email_sent = send_otp_email(email, otp)
    
    if not email_sent:
        # Log for debugging (in production, email should succeed)
        logger.warning("[OTP DEBUG] OTP for %s: %s", email, otp)
    
    return success_response({
        "message": "OTP sent to your email",
        "email": email
    })

@router.get("/test-email")
def test_email():
    """
    Diagnostic endpoint to test email configuration.
    Returns status of email service connectivity.
    """
    result = test_email_connection()
    status_code = 200 if result["status"] == "connected" else 503
    return JSONResponse(content=success_response(result), status_code=status_code)

@router.post("/verify-otp-register")
def verify_otp_register(email: str = Form(...), otp: str = Form(...), password: str = Form(...)):
    email = email.lower().strip()
    record = OTP_STORE.get(email)
    
    if not record or record["otp"] != otp or time.time() > record["expires"]:
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")
        
    with get_db() as conn:
        user = get_user_by_email(conn, email)
        if user:
            raise HTTPException(status_code=400, detail="Email already registered")
            
        hashed = hash_password(password)
        # Using ? parameter binding matching files.py
        settings = get_settings()
        is_postgres = settings.database_url and settings.database_url.startswith("postgres")
        placeholder = "%s" if is_postgres else "?"
        
        conn.execute(
            f"INSERT INTO users (email, password_hash, role) VALUES ({placeholder}, {placeholder}, 'user')",
            (email, hashed)
        )
        
    if email in OTP_STORE:
        del OTP_STORE[email]
    
    return success_response({"message": "Account created successfully"})
