from __future__ import annotations

from fastapi import APIRouter, Body, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import get_db
from ..schemas import LoginRequest, UserOut
from ..security import create_access_token, verify_password
from ..services.audit import get_logger
from ..services.files import get_user_by_email
from ..services.email import test_email_connection
from ..utils.response import success_response, error_response
from ..deps import require_current_user

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

@router.post("/request-password-reset")
def request_password_reset(payload: dict = Body(...)):
    email = str(payload.get("email", "")).strip().lower()
    return success_response({"message": f"If {email} exists, a reset link was sent."})


@router.get("/test-email")
def test_email():
    """
    Diagnostic endpoint to test email configuration.
    Returns status of email service connectivity.
    """
    result = test_email_connection()
    status_code = 200 if result["status"] == "connected" else 503
    return JSONResponse(content=success_response(result), status_code=status_code)

# Email OTP registration/verification removed per dev preference.


@router.post("/register")
def register(full_name: str = Form(""), email: str = Form(...), password: str = Form(...)):
    """Simple registration endpoint (no email OTP)."""
    email = email.lower().strip()
    with get_db() as conn:
        user = get_user_by_email(conn, email)
        if user:
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed = hash_password(password)
        settings = get_settings()
        is_postgres = settings.database_url and settings.database_url.startswith("postgres")
        placeholder = "%s" if is_postgres else "?"

        conn.execute(
            f"INSERT INTO users (email, password_hash, role) VALUES ({placeholder}, {placeholder}, 'user')",
            (email, hashed)
        )
    return success_response({"message": "Account created successfully"})
