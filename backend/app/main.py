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

import time
from .config import get_settings
from .database import init_db
from .routes import include_all_routers
from .services.audit import get_logger
from .services.dam import start_stream_worker, stop_stream_worker, record_event
from .services.tasks import cleanup_loop, scheduled_reports_loop, virus_scan_loop
from .utils.response import error_response, success_response

settings = get_settings()
logger = get_logger()


def _log_upload_failure(request: Request, *, action: str, message: str, metadata: dict | None = None) -> None:
    if request.url.path != "/files/api-upload":
        return
    source_ip = request.client.host if request.client else None
    try:
        record_event(
            event_type="security",
            severity="high",
            action=action,
            status="failure",
            message=message,
            source_ip=source_ip,
            metadata=metadata or {},
        )
    except Exception:
        logger.debug("Upload failure event logging skipped", exc_info=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_stream_worker()
    
    # Start background tasks
    task_cleanup = asyncio.create_task(cleanup_loop())
    task_reports = asyncio.create_task(scheduled_reports_loop())
    task_virus_scan = asyncio.create_task(virus_scan_loop())
    
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
        task_virus_scan.cancel()
        stop_stream_worker()
        for t in (task_cleanup, task_reports, task_virus_scan):
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

@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    duration = time.time() - start_time
    status_code = response.status_code
    
    # Skip logging for static files and health checks to avoid noise
    if request.url.path.startswith(("/static", "/health")):
        return response

    # Try to identify user from headers (simplified)
    actor_email = request.headers.get("x-user-email")
    
    # Record event in DAM
    try:
        record_event(
            event_type="web_request",
            severity="low" if status_code < 400 else "medium",
            action=f"http_{request.method.lower()}",
            status="success" if status_code < 400 else "failure",
            message=f"{request.method} {request.url.path} -> {status_code}",
            source_ip=request.client.host if request.client else "unknown",
            actor_email=actor_email,
            metadata={
                "path": request.url.path,
                "method": request.method,
                "status_code": status_code,
                "duration_ms": int(duration * 1000),
                "query_params": str(request.query_params),
                "user_agent": request.headers.get("user-agent"),
            }
        )
    except Exception:
        # Don't let logging failure break the app
        pass
        
    return response

# Exception Handlers
def add_cors(request: Request, response: JSONResponse) -> JSONResponse:
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled Exception: %s\n%s", exc, traceback.format_exc())
    _log_upload_failure(
        request,
        action="upload_unhandled_failure",
        message="Unhandled exception during upload processing",
        metadata={"error": str(exc)},
    )
    return add_cors(request, JSONResponse(
        status_code=500,
        content=error_response("Internal Server Error")
    ))

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path == "/files/api-upload" and exc.status_code not in {406, 503}:
        _log_upload_failure(
            request,
            action="upload_http_failure",
            message="Upload request failed with HTTP exception",
            metadata={"status_code": exc.status_code, "detail": str(exc.detail)},
        )
    return add_cors(request, JSONResponse(
        status_code=exc.status_code,
        content=error_response(exc.detail)
    ))

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    _log_upload_failure(
        request,
        action="upload_validation_failure",
        message="Upload request validation failed",
        metadata={"errors": exc.errors()},
    )
    return add_cors(request, JSONResponse(
        status_code=400,
        content=error_response(f"Invalid request parameters: {exc.errors()}")
    ))

# Static Files
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Routes
include_all_routers(app)

@app.get("/health")
def health_check():
    return success_response({"status": "healthy"})
