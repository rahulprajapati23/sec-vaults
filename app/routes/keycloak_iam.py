from __future__ import annotations

import re
from fastapi import APIRouter, Form, HTTPException, status
from ..config import get_settings
from ..services.keycloak_iam import KeycloakIAM, KeycloakUnavailableError

router = APIRouter(prefix="/iam", tags=["iam"])

def _strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    checks = [
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[^A-Za-z0-9]", password),
    ]
    return all(checks)

@router.get("/status")
def iam_status():
    s = get_settings()
    return {
        "keycloak_enabled": s.keycloak_enabled,
        "realm": s.keycloak_realm,
        "server_configured": bool(s.keycloak_server_url),
    }

@router.post("/register")
def keycloak_register(
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("REQUESTER"),
):
    requested_role = role.strip().upper()
    if requested_role not in {"OWNER", "REQUESTER", "ADMIN"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="role must be OWNER, REQUESTER, or ADMIN")
    if not _strong_password(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password policy: min 12 chars with uppercase, lowercase, number, and special character",
        )
    try:
        iam = KeycloakIAM()
        result = iam.register_user(email=email, username=username, password=password, role=requested_role)
        return {"message": "registered", "user": result}
    except KeycloakUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Registration failed: {exc}") from exc

@router.post("/login")
def keycloak_login(username: str = Form(...), password: str = Form(...)):
    try:
        iam = KeycloakIAM()
        token = iam.login(username=username, password=password)
        return token
    except KeycloakUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Login failed: {exc}") from exc
