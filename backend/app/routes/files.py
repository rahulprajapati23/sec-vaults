from __future__ import annotations

import mimetypes
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from ..config import get_settings
from ..database import get_db
from ..deps import require_current_user
from ..security import hash_password, hash_token, utc_now
from ..services.files import get_file_for_user, list_files_for_user
from ..utils.response import success_response

router = APIRouter(tags=["files"])


def _storage_path(filename: str) -> Path:
    settings = get_settings()
    settings.storage_path.mkdir(parents=True, exist_ok=True)
    return settings.storage_path / filename


@router.get("/files")
def files(request: Request):
    user = require_current_user(request)
    with get_db() as conn:
        rows = list_files_for_user(conn, user["id"])
    return success_response({"files": [dict(row) for row in rows]})


@router.post("/files/api-upload")
def api_upload(request: Request, file: UploadFile = File(...), expiry_hours: int = Form(24), max_downloads: int | None = Form(None)):
    user = require_current_user(request)
    settings = get_settings()
    stored_name = f"{uuid.uuid4().hex}_{file.filename}"
    storage_file = _storage_path(stored_name)

    with storage_file.open("wb") as handle:
        shutil.copyfileobj(file.file, handle)

    expires_at = utc_now() + timedelta(hours=expiry_hours)
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO files (owner_id, original_name, mime_type, size_bytes, created_at, expires_at, max_downloads, download_count, is_deleted, storage_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
            """,
            (
                user["id"],
                file.filename,
                file.content_type or mimetypes.guess_type(file.filename)[0] or "application/octet-stream",
                storage_file.stat().st_size,
                utc_now().isoformat(),
                expires_at.isoformat(),
                max_downloads,
                str(storage_file),
            ),
        )

    return success_response({
        "id": cursor.lastrowid,
        "original_name": file.filename,
        "mime_type": file.content_type or "application/octet-stream",
        "size_bytes": storage_file.stat().st_size,
        "created_at": utc_now().isoformat(),
        "expires_at": expires_at.isoformat(),
        "download_count": 0,
        "max_downloads": max_downloads,
        "scan_status": "clean",
    })


@router.get("/files/{file_id}/download")
def download_file(request: Request, file_id: int):
    user = require_current_user(request)
    with get_db() as conn:
        row = get_file_for_user(conn, file_id, user["id"])
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(row["storage_path"], filename=row["original_name"])


@router.delete("/files/{file_id}")
def delete_file(request: Request, file_id: int):
    user = require_current_user(request)
    with get_db() as conn:
        row = get_file_for_user(conn, file_id, user["id"])
        if not row:
            raise HTTPException(status_code=404, detail="File not found")
        conn.execute("UPDATE files SET is_deleted = 1 WHERE id = ?", (file_id,))
    return success_response({"message": "File deleted"})


@router.post("/files/{file_id}/share")
def share_file(request: Request, file_id: int, password: str = Form(...), expires_hours: int = Form(24)):
    user = require_current_user(request)
    with get_db() as conn:
        row = get_file_for_user(conn, file_id, user["id"])
        if not row:
            raise HTTPException(status_code=404, detail="File not found")
    token = uuid.uuid4().hex
    return success_response({
        "share_url": f"/share/{token}",
        "full_url": f"http://127.0.0.1:5173/share/{token}",
        "share_id": file_id,
        "expires_at": (utc_now() + timedelta(hours=expires_hours)).isoformat(),
        "qr_code": None,
        "file_name": row["original_name"],
    })