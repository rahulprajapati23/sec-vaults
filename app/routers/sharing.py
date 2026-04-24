from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse

from ..database import get_db
from ..security import hash_token, is_expired, verify_password
from ..services.audit import get_logger
from ..services.crypto import decrypt_bytes
from ..services.dam import record_event
from ..services.files import (
    file_is_download_limited,
    get_file_by_id,
    get_share_by_token_hash,
    increment_share_failure,
    log_download,
    mark_download,
    set_share_blocked_until,
    share_attempt_limit_reached,
    share_is_blocked,
    touch_share,
)
from ..config import get_settings

router = APIRouter(prefix="/share", tags=["share"])
logger = get_logger()


@router.get("/{token}", response_class=HTMLResponse)
def share_form(token: str, request: Request):
    return request.app.state.templates.TemplateResponse(
        "share_access.html",
        {"request": request, "token": token, "error": None},
    )


@router.post("/{token}")
def share_download(token: str, request: Request, password: str = Form(...)):
    token_hash = hash_token(token)
    with get_db() as conn:
        share_row = get_share_by_token_hash(conn, token_hash)
        if not share_row:
            record_event(
                event_type="intrusion",
                severity="high",
                action="unauthorized_access",
                status="failed",
                message="Share token not found",
                actor_user_id=None,
                actor_email=None,
                request=request,
            )
            return request.app.state.templates.TemplateResponse(
                "share_access.html",
                {"request": request, "token": token, "error": "Share link not found"},
                status_code=status.HTTP_404_NOT_FOUND,
            )
        if is_expired(share_row["expires_at"]):
            record_event(
                event_type="file_access",
                severity="medium",
                action="share_download",
                status="failed",
                message="Expired share link access attempted",
                actor_user_id=None,
                actor_email=None,
                request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"]},
            )
            return request.app.state.templates.TemplateResponse(
                "share_access.html",
                {"request": request, "token": token, "error": "Share link expired"},
                status_code=status.HTTP_410_GONE,
            )
        if share_is_blocked(share_row):
            record_event(
                event_type="intrusion",
                severity="high",
                action="brute_force_detected",
                status="blocked",
                message="Blocked share link access attempted",
                actor_user_id=None,
                actor_email=None,
                request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"]},
            )
            return request.app.state.templates.TemplateResponse(
                "share_access.html",
                {"request": request, "token": token, "error": "Share link temporarily blocked"},
                status_code=status.HTTP_423_LOCKED,
            )
        if share_attempt_limit_reached(share_row):
            record_event(
                event_type="intrusion",
                severity="high",
                action="brute_force_detected",
                status="blocked",
                message="Share link blocked due to failed attempts",
                actor_user_id=None,
                actor_email=None,
                request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"]},
            )
            return request.app.state.templates.TemplateResponse(
                "share_access.html",
                {"request": request, "token": token, "error": "Share link blocked after failed attempts"},
                status_code=status.HTTP_423_LOCKED,
            )
        if not verify_password(password, share_row["password_hash"]):
            updated = increment_share_failure(conn, share_row["id"])
            if share_attempt_limit_reached(updated):
                set_share_blocked_until(conn, share_row["id"], datetime.now(timezone.utc) + timedelta(minutes=30))
            log_download(
                conn,
                file_id=share_row["file_id"],
                user_id=None,
                share_link_id=share_row["id"],
                success=False,
                reason="invalid share password",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            logger.warning("share_failed share_id=%s", share_row["id"])
            record_event(
                event_type="intrusion",
                severity="high" if share_attempt_limit_reached(updated) else "medium",
                action="share_download",
                status="failed",
                message="Invalid share password",
                actor_user_id=None,
                actor_email=None,
                request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"], "failed_attempts": updated["failed_attempts"]},
            )
            return request.app.state.templates.TemplateResponse(
                "share_access.html",
                {"request": request, "token": token, "error": "Invalid password"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        file_row = get_file_by_id(conn, share_row["file_id"])
        if not file_row or file_row["is_deleted"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        if is_expired(file_row["expires_at"]):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="File expired")
        if file_is_download_limited(file_row):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Download limit reached")
        encrypted_blob = open(file_row["storage_path"], "rb").read()
        plaintext = decrypt_bytes(
            encrypted_blob,
            file_row["file_nonce"],
            file_row["encrypted_key"],
            file_row["key_nonce"],
            get_settings().master_key,
        )
        mark_download(conn, file_row["id"])
        touch_share(conn, share_row["id"])
        log_download(
            conn,
            file_id=file_row["id"],
            user_id=None,
            share_link_id=share_row["id"],
            success=True,
            reason="share download",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    logger.info("share_download share_id=%s file_id=%s", share_row["id"], file_row["id"])
    record_event(
        event_type="file_access",
        severity="medium",
        action="share_download",
        status="success",
        message="File downloaded via share link",
        actor_user_id=None,
        actor_email=None,
        request=request,
        file_id=file_row["id"],
        file_name=file_row["original_name"],
        file_path=file_row["storage_path"],
        metadata={"share_id": share_row["id"]},
    )
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=file_row["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'},
    )
