from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
import httpx

from ..database import get_db
from ..security import hash_password, hash_token, is_expired, max_file_size_bytes
from ..services.audit import get_logger
from ..services.crypto import decrypt_bytes, encrypt_bytes
from ..services.dam import record_event
from ..services.files import (
    create_share_link,
    delete_expired_files,
    file_is_download_limited,
    get_file_by_id,
    get_file_for_user,
    get_share_by_token_hash,
    increment_share_failure,
    list_files_for_user,
    log_download,
    mark_download,
    get_file_owner_email,
    set_share_blocked_until,
    share_attempt_limit_reached,
    share_is_blocked,
    store_encrypted_file,
    touch_share,
    remove_file_blob,
)
from ..config import get_settings
from ..deps import require_current_user

router = APIRouter(prefix="/files", tags=["files"])
logger = get_logger()

@router.get("")
def list_files(request: Request):
    user = require_current_user(request)
    with get_db() as conn:
        files = list_files_for_user(conn, user["id"])
    safe_files = [
        {
            "id": row["id"],
            "original_name": row["original_name"],
            "mime_type": row["mime_type"],
            "size_bytes": row["size_bytes"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "download_count": row["download_count"],
            "max_downloads": row["max_downloads"],
            "scan_status": row["scan_status"] if "scan_status" in row.keys() else "clean",
        }
        for row in files
    ]
    return {"files": safe_files}

@router.post("/api-upload")
async def upload_file_api(
    request: Request,
    file: UploadFile = File(...),
    expiry_hours: int = Form(24),
    max_downloads: int | None = Form(None),
):
    """Unified API upload endpoint."""
    user = require_current_user(request)
    if expiry_hours < 1 or expiry_hours > 720:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expiry_hours must be between 1 and 720")

    original_name = file.filename or "upload.bin"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty uploads are not allowed")
    if len(content) > max_file_size_bytes():
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds maximum size")

    settings = get_settings()
    scan_status = "clean"
    if settings.virustotal_api_key:
        file_hash = hashlib.sha256(content).hexdigest()
        async with httpx.AsyncClient() as client:
            try:
                vt_resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": settings.virustotal_api_key},
                    timeout=5.0,
                )
                if vt_resp.status_code == 200:
                    stats = vt_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        scan_status = "infected"
                        record_event(
                            event_type="security", severity="critical", action="malware_detected",
                            status="blocked", message="Malware detected during upload",
                            actor_user_id=user["id"], actor_email=user["email"], request=request,
                            metadata={"file_name": original_name, "sha256": file_hash, "vt_stats": stats},
                        )
                        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Malware detected. Upload blocked.")
            except Exception as e:
                logger.error(f"VirusTotal API error: {e}")

    payload = encrypt_bytes(content, settings.master_key)
    with get_db() as conn:
        record = store_encrypted_file(
            conn, owner_id=user["id"], original_name=original_name,
            mime_type=file.content_type or "application/octet-stream",
            size_bytes=len(content), encrypted_blob=payload.encrypted_content,
            key_nonce=payload.key_nonce, encrypted_key=payload.encrypted_key,
            file_nonce=payload.file_nonce, expiry_hours=expiry_hours,
            max_downloads=max_downloads,
        )
    return {
        "id": record["id"],
        "original_name": record["original_name"],
        "size_bytes": len(content),
        "scan_status": scan_status,
        "message": "File uploaded and encrypted successfully",
    }

@router.get("/{file_id}/download")
def download_file(request: Request, file_id: int):
    user = require_current_user(request)
    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        
        from ..services.files import get_file_blob
        blob_path = file_row["storage_path"]
        encrypted_blob = get_file_blob(blob_path)
        plaintext = decrypt_bytes(
            encrypted_blob, file_row["file_nonce"], file_row["encrypted_key"],
            file_row["key_nonce"], get_settings().master_key,
        )
        mark_download(conn, file_id)
        
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=file_row["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'},
    )

@router.delete("/{file_id}")
def delete_file(request: Request, file_id: int):
    user = require_current_user(request)
    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        remove_file_blob(file_row["storage_path"])
        conn.execute("UPDATE files SET is_deleted = 1 WHERE id = ?", (file_id,))
    return {"success": True}
