from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..database import get_db
from ..services.files import list_files_for_user

router = APIRouter(tags=["pages"])


@router.get("/")
def index(request: Request):
    token = request.cookies.get("access_token")
    if token:
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/login")


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return request.app.state.templates.TemplateResponse("register.html", {"request": request, "error": None})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return request.app.state.templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    from ..main import require_current_user

    try:
        user = require_current_user(request)
    except Exception:
        return RedirectResponse(url="/login")
    with get_db() as conn:
        files = list_files_for_user(conn, user["id"])
    return request.app.state.templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "files": files},
    )


@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    from ..main import require_current_user

    try:
        require_current_user(request)
    except Exception:
        return RedirectResponse(url="/login")
    return request.app.state.templates.TemplateResponse("upload.html", {"request": request})
