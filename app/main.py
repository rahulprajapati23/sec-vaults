from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
import traceback
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import get_settings
from .database import get_db, init_db
from .routers import analytics, auth, auth_otp, dam, files, keycloak_iam, mfa, pages, reports, sessions, sharing, vault_access, ws_alerts, system_utils, siem
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


async def _scheduled_reports_loop() -> None:
    """Fire daily/weekly reports at 00:00 UTC automatically."""
    from .services.reports import send_daily_report, send_weekly_report
    from datetime import datetime, timezone
    last_daily: str | None = None
    last_weekly: str | None = None
    while True:
        now = datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        week = now.strftime("%Y-W%U")
        if now.hour == 0 and last_daily != today:
            try:
                send_daily_report()
                last_daily = today
                logger.info("scheduled_daily_report_sent date=%s", today)
            except Exception as exc:
                logger.warning("scheduled_daily_report_failed error=%s", exc)
        if now.weekday() == 0 and now.hour == 0 and last_weekly != week:
            try:
                send_weekly_report()
                last_weekly = week
                logger.info("scheduled_weekly_report_sent week=%s", week)
            except Exception as exc:
                logger.warning("scheduled_weekly_report_failed error=%s", exc)
        await asyncio.sleep(60)  # check every minute

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_stream_worker()
    task_cleanup = asyncio.create_task(_cleanup_loop())
    task_reports = asyncio.create_task(_scheduled_reports_loop())
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
        task_cleanup.cancel()
        task_reports.cancel()
        stop_stream_worker()
        for t in (task_cleanup, task_reports):
            try:
                await t
            except asyncio.CancelledError:
                pass


from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Secure File Storage System", lifespan=lifespan)

# Allow React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled Exception: %s\n%s", exc, traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "code": "INTERNAL_ERROR"}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "code": getattr(exc, "code", "AUTH_FAILED" if exc.status_code in (401, 403) else "API_ERROR")}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"error": "Invalid request parameters", "code": "VALIDATION_FAILED", "details": exc.errors()}
    )


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
app.include_router(ws_alerts.router)
app.include_router(system_utils.router)
app.include_router(siem.router)


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
        user = get_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_roles(request: Request, allowed_roles: set[str]):
    user = require_current_user(request)
    role = _normalize_role(dict(user).get("role"))
    if role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return user



def require_admin_user(request: Request):
    return require_roles(request, {"ADMIN"})


