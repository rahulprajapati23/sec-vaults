from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import get_settings
from .database import get_db, init_db
from .routers import analytics, auth, auth_otp, dam, files, keycloak_iam, mfa, pages, reports, sessions, sharing, vault_access
from .security import decode_token
from .services.audit import get_logger
from .services.dam import record_event, start_stream_worker, stop_stream_worker
from .services.retention import run_data_retention_cleanup
from .services.files import delete_expired_files, get_user_by_id

settings = get_settings()
logger = get_logger()
init_db()


def _load_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
    return templates


async def _cleanup_loop() -> None:
    while True:
        with get_db() as conn:
            deleted = delete_expired_files(conn)
            run_data_retention_cleanup(conn)
        if deleted:
            logger.info("cleanup deleted=%s", deleted)
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_stream_worker()
    task = asyncio.create_task(_cleanup_loop())
    record_event(
        event_type="system",
        severity="low",
        action="startup",
        status="success",
        message="Application startup",
        actor_user_id=None,
        actor_email=None,
        metadata={"service": "secure_file_storage"},
    )
    try:
        yield
    finally:
        task.cancel()
        stop_stream_worker()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Secure File Storage System", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")
app.state.templates = _load_templates()
app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(auth_otp.router)
app.include_router(mfa.router)
app.include_router(files.router)
app.include_router(sharing.router)
app.include_router(sessions.router)
app.include_router(dam.router)
app.include_router(analytics.router)
app.include_router(reports.router)
app.include_router(vault_access.router)
app.include_router(keycloak_iam.router)


def _normalize_role(role: str | None) -> str:
    value = (role or "").strip().lower()
    if value == "owner":
        return "OWNER"
    if value == "admin":
        return "ADMIN"
    if value in {"auditor", "requester", "user"}:
        return "REQUESTER"
    return "REQUESTER"


def require_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(token)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    with get_db() as conn:
        user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_roles(request: Request, allowed_roles: set[str]):
    user = require_current_user(request)
    role = _normalize_role(user.get("role"))
    if role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return user


def require_admin_user(request: Request):
    return require_roles(request, {"ADMIN"})


