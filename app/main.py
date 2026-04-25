from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import traceback
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import init_db
from .routes import include_all_routers
from .services.audit import get_logger
from .services.dam import start_stream_worker, stop_stream_worker
from .services.tasks import cleanup_loop, scheduled_reports_loop
from .utils import load_templates

settings = get_settings()
logger = get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_stream_worker()
    
    # Start background tasks
    task_cleanup = asyncio.create_task(cleanup_loop())
    task_reports = asyncio.create_task(scheduled_reports_loop())
    
    from .services.dam import record_event
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

app = FastAPI(title="Secure File Storage System", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_allow_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception Handlers
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

# Static Files & Templates
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")
app.state.templates = load_templates()

# Routes
include_all_routers(app)


