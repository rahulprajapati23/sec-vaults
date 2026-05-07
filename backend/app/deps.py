from __future__ import annotations
from fastapi import HTTPException, Request, status
from .database import get_db
from .security import decode_token

# Helper to normalize roles
def normalize_role(role: str | None) -> str:
    if not role: return "USER"
    return role.strip().upper()

def require_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = decode_token(token)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    with get_db() as conn:
        # Simplified user fetch
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return dict(user)

def require_roles(request: Request, allowed_roles: set[str]):
    user = require_current_user(request)
    role = normalize_role(user.get("role"))
    if role not in allowed_roles:
        print(f"DEBUG: Access denied for {user.get('email')}. Role: {role}, Required: {allowed_roles}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return user

def require_admin_user(request: Request):
    return require_roles(request, {"ADMIN"})
