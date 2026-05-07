from __future__ import annotations

import base64
import io
import mimetypes
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

import qrcode

from ..config import get_settings
from ..database import get_db
from ..deps import require_current_user
from ..security import hash_password, hash_token, utc_now, verify_password
from ..services.files import get_file_for_user, list_files_for_user, perform_virustotal_scan
from ..utils.response import success_response

router = APIRouter(tags=["files"])


def _storage_path(filename: str) -> Path:
    settings = get_settings()
    settings.storage_path.mkdir(parents=True, exist_ok=True)
    return settings.storage_path / filename


def _build_qr_data_uri(text: str) -> str | None:
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(text)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception:
        return None


def _placeholder(conn) -> str:
    return "?" if conn.__class__.__module__.startswith("sqlite3") else "%s"


def _is_infected_file(row) -> bool:
    if not row:
        return False
    payload = dict(row)
    status = str(payload.get("virus_scan_status") or payload.get("scan_status") or "").strip().lower()
    return status == "infected"


@router.get("/files")
def files(request: Request):
    user = require_current_user(request)
    with get_db() as conn:
        rows = list_files_for_user(conn, user["id"])
    files_payload = []
    for row in rows:
        payload = dict(row)
        if "scan_status" not in payload:
            payload["scan_status"] = payload.get("virus_scan_status") or "pending"
        files_payload.append(payload)
    return success_response({"files": files_payload})


@router.post("/files/api-upload")
def api_upload(request: Request, file: UploadFile = File(...), expiry_hours: int = Form(24), max_downloads: int | None = Form(None)):
    user = require_current_user(request)
    settings = get_settings()
    source_ip = request.client.host if request.client else None
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
        file_id = cursor.lastrowid

    # Run VirusTotal scan (best-effort). This will update DB with final status.
    scan_status = perform_virustotal_scan(str(storage_file), file_id)
    if os.getenv("SECVAULT_FORCE_INFECTED_UPLOAD", "false").strip().lower() in {"1", "true", "yes", "on"}:
        scan_status = "infected"

    # Fail-safe policy: only clean files are accepted.
    # Critical order for SOC visibility: log threat first, then block/quarantine response.
    if scan_status in {"infected", "error"}:
        event_action = "malware_detected" if scan_status == "infected" else "malware_scan_failed"
        event_message = (
            "Malicious file detected during upload scan"
            if scan_status == "infected"
            else "Upload blocked because malware scan could not be completed"
        )
        status_code = 406 if scan_status == "infected" else 503
        response_detail = (
            "Malware detected and quarantined"
            if scan_status == "infected"
            else "Upload blocked: malware scan failed"
        )
        with get_db() as conn:
            placeholder = _placeholder(conn)
            conn.execute(
                f"""
                INSERT INTO dam_events (
                    event_id, event_type, severity, actor_user_id, actor_email,
                    source_ip, action, status, message, metadata_json, created_at
                ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                """,
                (
                    str(uuid.uuid4()),
                    "security",
                    "high",
                    user["id"],
                    user.get("email"),
                    source_ip,
                    event_action,
                    "failure",
                    event_message,
                    json.dumps({
                        "file_id": file_id,
                        "file_name": file.filename,
                        "scan_status": scan_status,
                    }, ensure_ascii=True),
                    utc_now().isoformat(),
                ),
            )
            conn.execute(
                f"UPDATE files SET is_deleted = 1 WHERE id = {placeholder}",
                (file_id,),
            )
            conn.commit()
        try:
            storage_file.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(status_code=status_code, detail=response_detail)

    return success_response({
        "id": file_id,
        "original_name": file.filename,
        "mime_type": file.content_type or "application/octet-stream",
        "size_bytes": storage_file.stat().st_size,
        "created_at": utc_now().isoformat(),
        "expires_at": expires_at.isoformat(),
        "download_count": 0,
        "max_downloads": max_downloads,
        "scan_status": scan_status,
        "virus_scan_status": scan_status,
    })


@router.get("/files/{file_id}/download")
def download_file(request: Request, file_id: int):
    user = require_current_user(request)
    with get_db() as conn:
        row = get_file_for_user(conn, file_id, user["id"])
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    if _is_infected_file(row):
        raise HTTPException(status_code=406, detail="File blocked: malware detected")
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
    settings = get_settings()
    with get_db() as conn:
        row = get_file_for_user(conn, file_id, user["id"])
        if not row:
            raise HTTPException(status_code=404, detail="File not found")
        if _is_infected_file(row):
            raise HTTPException(status_code=406, detail="Cannot share infected file")
        token = uuid.uuid4().hex
        token_hash = hash_token(token)
        password_hash = hash_password(password)
        expires_at = utc_now() + timedelta(hours=expires_hours)
        placeholder = _placeholder(conn)
        cursor = conn.execute(
            """
            INSERT INTO share_links (
                token_hash, file_id, password_hash, created_by, created_at, expires_at,
                max_failed_attempts, failed_attempts, blocked_until, last_accessed_at
            ) VALUES ({0}, {0}, {0}, {0}, {0}, {0}, {0}, 0, NULL, NULL)
            """.format(placeholder),
            (
                token_hash,
                file_id,
                password_hash,
                user["id"],
                utc_now().isoformat(),
                expires_at.isoformat(),
                5,
            ),
        )
        share_id = cursor.lastrowid

    share_path = f"/share/{token}"
    full_url = f"{settings.frontend_app_url}{share_path}"
    qr_code = _build_qr_data_uri(full_url)
    return success_response({
        "share_url": full_url,
        "full_url": full_url,
        "share_id": share_id,
        "expires_at": expires_at.isoformat(),
        "qr_code": qr_code,
        "file_name": row["original_name"],
    })


@router.get("/share/{token}")
def share_details(token: str):
    token_hash = hash_token(token)
    with get_db() as conn:
        placeholder = _placeholder(conn)
        share = conn.execute(
            f"SELECT * FROM share_links WHERE token_hash = {placeholder}",
            (token_hash,),
        ).fetchone()
        if not share:
            raise HTTPException(status_code=404, detail="Share link not found")
        file_row = conn.execute(
            f"SELECT original_name, expires_at FROM files WHERE id = {placeholder}",
            (share["file_id"],),
        ).fetchone()
    return success_response({
        "file_name": file_row["original_name"] if file_row else "Shared File",
        "expires_at": share["expires_at"],
        "password_required": True,
    })


@router.post("/share/{token}/download")
def download_shared_file(request: Request, token: str, password: str = Form(...)):
    token_hash = hash_token(token)
    source_ip = request.client.host if request.client else None
    with get_db() as conn:
        placeholder = _placeholder(conn)
        share = conn.execute(
            f"SELECT * FROM share_links WHERE token_hash = {placeholder}",
            (token_hash,),
        ).fetchone()
        if not share:
            raise HTTPException(status_code=404, detail="Share link not found")

        blocked_until = share["blocked_until"]
        if blocked_until and blocked_until > utc_now().isoformat():
            raise HTTPException(status_code=423, detail="Share link is temporarily blocked")

        if share["expires_at"] and utc_now().isoformat() >= share["expires_at"]:
            raise HTTPException(status_code=410, detail="Share link expired")

        if not verify_password(password, share["password_hash"]):
            failed_attempts = int(share["failed_attempts"] or 0) + 1
            blocked_until_value = None
            severity = "medium"
            if failed_attempts >= int(share["max_failed_attempts"] or 5):
                blocked_until_value = (utc_now() + timedelta(minutes=15)).isoformat()
                severity = "high"
            conn.execute(
                f"UPDATE share_links SET failed_attempts = {placeholder}, blocked_until = {placeholder} WHERE token_hash = {placeholder}",
                (failed_attempts, blocked_until_value, token_hash),
            )
            event_placeholder = _placeholder(conn)
            conn.execute(
                f"""
                INSERT INTO dam_events (
                    event_id, event_type, severity, actor_user_id, actor_email,
                    source_ip, action, status, message, metadata_json, created_at
                ) VALUES ({event_placeholder}, {event_placeholder}, {event_placeholder}, NULL, NULL, {event_placeholder}, {event_placeholder}, {event_placeholder}, {event_placeholder}, {event_placeholder}, {event_placeholder})
                """,
                (
                    str(uuid.uuid4()),
                    "security",
                    severity,
                    source_ip,
                    "share_password_failed",
                    "failure",
                    "Invalid password used for shared file access",
                    json.dumps({
                        "file_id": share["file_id"],
                        "share_id": share["id"],
                        "failed_attempts": failed_attempts,
                        "blocked_until": blocked_until_value,
                    }, ensure_ascii=True),
                    utc_now().isoformat(),
                ),
            )
            conn.commit()
            raise HTTPException(status_code=401, detail="Invalid share password")

        conn.execute(
            f"UPDATE share_links SET failed_attempts = 0, blocked_until = NULL, last_accessed_at = {placeholder} WHERE token_hash = {placeholder}",
            (utc_now().isoformat(), token_hash),
        )
        file_row = conn.execute(
            f"SELECT * FROM files WHERE id = {placeholder} AND is_deleted = 0",
            (share["file_id"],),
        ).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if _is_infected_file(file_row):
            raise HTTPException(status_code=406, detail="File blocked: malware detected")

    return FileResponse(file_row["storage_path"], filename=file_row["original_name"])