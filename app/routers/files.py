from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

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

router = APIRouter(prefix="/files", tags=["files"])
logger = get_logger()


@router.get("")
def list_files(request: Request):
    from ..main import require_current_user

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
        }
        for row in files
    ]
    record_event(
        event_type="file_access",
        severity="low",
        action="read",
        status="success",
        message="Listed user files",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        metadata={"file_count": len(safe_files)},
    )
    return {"files": safe_files}


@router.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    expiry_hours: int = Form(24),
    max_downloads: int | None = Form(None),
):
    from ..main import require_current_user

    user = require_current_user(request)
    if expiry_hours < 1 or expiry_hours > 720:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expiry_hours must be between 1 and 720")
    if max_downloads is not None and max_downloads <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="max_downloads must be positive")

    original_name = file.filename or "upload.bin"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty uploads are not allowed")
    if len(content) > max_file_size_bytes():
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds maximum size")

    payload = encrypt_bytes(content, get_settings().master_key)
    with get_db() as conn:
        record = store_encrypted_file(
            conn,
            owner_id=user["id"],
            original_name=original_name,
            mime_type=file.content_type or "application/octet-stream",
            size_bytes=len(content),
            encrypted_blob=payload.encrypted_content,
            key_nonce=payload.key_nonce,
            encrypted_key=payload.encrypted_key,
            file_nonce=payload.file_nonce,
            expiry_hours=expiry_hours,
            max_downloads=max_downloads,
        )
    logger.info("upload user_id=%s file_id=%s name=%s", user["id"], record["id"], record["original_name"])
    record_event(
        event_type="file_access",
        severity="low",
        action="write",
        status="success",
        message="Encrypted file uploaded",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        file_id=record["id"],
        file_name=record["original_name"],
        file_path=record["storage_path"],
        metadata={"size_bytes": len(content), "mime_type": file.content_type},
    )
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{file_id}/download")
def download_file(request: Request, file_id: int):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            owner_email = get_file_owner_email(conn, file_id)
            record_event(
                event_type="intrusion",
                severity="high",
                action="unauthorized_access",
                status="failed",
                message="User attempted to access non-owned file",
                actor_user_id=user["id"],
                actor_email=user["email"],
                request=request,
                file_id=file_id,
                metadata={"owner_email": owner_email},
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        if is_expired(file_row["expires_at"]):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="File expired")
        if file_is_download_limited(file_row):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Download limit reached")

        blob_path = file_row["storage_path"]
        encrypted_blob = open(blob_path, "rb").read()
        plaintext = decrypt_bytes(
            encrypted_blob,
            file_row["file_nonce"],
            file_row["encrypted_key"],
            file_row["key_nonce"],
            get_settings().master_key,
        )
        mark_download(conn, file_id)
        log_download(
            conn,
            file_id=file_id,
            user_id=user["id"],
            share_link_id=None,
            success=True,
            reason="owner download",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        updated = get_file_by_id(conn, file_id)

    logger.info("download user_id=%s file_id=%s", user["id"], file_id)
    owner_email = user["email"]
    record_event(
        event_type="file_access",
        severity="medium",
        action="download",
        status="success",
        message="Owner downloaded file",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        file_id=file_id,
        file_name=file_row["original_name"],
        file_path=file_row["storage_path"],
        metadata={"owner_email": owner_email, "download_count": updated["download_count"] if updated else None},
    )
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=file_row["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'},
    )


@router.post("/{file_id}/share")
def create_share(request: Request, file_id: int, password: str = Form(...), expires_hours: int = Form(24)):
    from ..main import require_current_user

    user = require_current_user(request)
    if expires_hours < 1 or expires_hours > 720:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_hours must be between 1 and 720")
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Share password must be at least 8 characters")

    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            record_event(
                event_type="intrusion",
                severity="high",
                action="unauthorized_access",
                status="failed",
                message="User attempted to create share for non-owned file",
                actor_user_id=user["id"],
                actor_email=user["email"],
                request=request,
                file_id=file_id,
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        share_row, token = create_share_link(
            conn,
            file_id=file_id,
            password_hash=hash_password(password),
            created_by=user["id"],
            expires_hours=expires_hours,
        )
    share_url = f"/share/{token}"
    logger.info("share_created user_id=%s file_id=%s share_id=%s", user["id"], file_id, share_row["id"])
    record_event(
        event_type="file_access",
        severity="low",
        action="share_create",
        status="success",
        message="Created password-protected share link",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        file_id=file_id,
        file_name=file_row["original_name"],
        file_path=file_row["storage_path"],
        metadata={"share_id": share_row["id"], "expires_at": share_row["expires_at"]},
    )
    return {"share_url": share_url, "expires_at": share_row["expires_at"]}


@router.post("/{file_id}/delete")
def delete_file(request: Request, file_id: int):
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            record_event(
                event_type="intrusion",
                severity="high",
                action="unauthorized_access",
                status="failed",
                message="User attempted to delete non-owned file",
                actor_user_id=user["id"],
                actor_email=user["email"],
                request=request,
                file_id=file_id,
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        remove_file_blob(file_row["storage_path"])
        conn.execute("UPDATE files SET is_deleted = 1 WHERE id = ?", (file_id,))
    logger.info("delete user_id=%s file_id=%s", user["id"], file_id)
    record_event(
        event_type="file_access",
        severity="medium",
        action="delete",
        status="success",
        message="Owner deleted file",
        actor_user_id=user["id"],
        actor_email=user["email"],
        request=request,
        file_id=file_id,
        file_name=file_row["original_name"],
        file_path=file_row["storage_path"],
    )
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/cleanup")
def cleanup_expired(request: Request):
    from ..main import require_current_user

    require_current_user(request)
    with get_db() as conn:
        removed = delete_expired_files(conn)
    record_event(
        event_type="system",
        severity="low",
        action="cleanup",
        status="success",
        message="Expired files cleanup run",
        actor_user_id=None,
        actor_email=None,
        request=request,
        metadata={"removed": removed},
    )
    return {"removed": removed}
