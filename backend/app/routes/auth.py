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
from ..utils.response import success_response, error_response
from ..deps import require_current_user

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
        samesite="lax",
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
