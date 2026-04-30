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
from .utils.response import error_response, success_response

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
def add_cors(request: Request, response: JSONResponse) -> JSONResponse:
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled Exception: %s\n%s", exc, traceback.format_exc())
    return add_cors(request, JSONResponse(
        status_code=500,
        content=error_response("Internal Server Error")
    ))

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return add_cors(request, JSONResponse(
        status_code=exc.status_code,
        content=error_response(exc.detail)
    ))

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return add_cors(request, JSONResponse(
        status_code=400,
        content=error_response(f"Invalid request parameters: {exc.errors()}")
    ))

# Static Files
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")

# Routes
include_all_routers(app)

@app.get("/health")
def health_check():
    return success_response({"status": "healthy"})
