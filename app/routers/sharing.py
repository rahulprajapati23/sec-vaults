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


@router.post("/{token}/api-download")
def share_api_download(token: str, request: Request, password: str = Form(...)):
    """
    API-compatible share download for React frontend.
    Validates token, expiry, brute-force state, and password — returns file stream or JSON error.
    Full audit logging on every access attempt.
    """
    from fastapi.responses import JSONResponse

    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    token_hash = hash_token(token)

    with get_db() as conn:
        share_row = get_share_by_token_hash(conn, token_hash)
        if not share_row:
            record_event(
                event_type="intrusion", severity="high", action="invalid_share_token",
                status="failed", message=f"Invalid share token attempted from {ip}",
                actor_user_id=None, actor_email=None, request=request,
                metadata={"ip": ip, "token_prefix": token[:8] + "…"},
            )
            return JSONResponse(status_code=404, content={"error": "Share link not found or invalid"})

        # Check expiry
        if is_expired(share_row["expires_at"]):
            record_event(
                event_type="file_access", severity="medium", action="expired_share_access",
                status="failed", message="Expired share link accessed",
                actor_user_id=None, actor_email=None, request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"], "expired_at": share_row["expires_at"]},
            )
            return JSONResponse(status_code=410, content={"error": "Share link has expired"})

        # Check if temporarily blocked (brute force cooldown)
        if share_is_blocked(share_row):
            record_event(
                event_type="intrusion", severity="high", action="brute_force_detected",
                status="blocked", message="Blocked share link access attempted",
                actor_user_id=None, actor_email=None, request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"], "blocked_until": share_row["blocked_until"], "ip": ip},
            )
            return JSONResponse(status_code=423, content={
                "error": "Too many failed attempts. This link is temporarily blocked.",
                "blocked_until": share_row["blocked_until"],
            })

        # Check permanent lockout
        if share_attempt_limit_reached(share_row):
            record_event(
                event_type="intrusion", severity="critical", action="share_permanently_locked",
                status="blocked", message="Share link permanently locked after max failed attempts",
                actor_user_id=None, actor_email=None, request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"], "failed_attempts": share_row["failed_attempts"]},
            )
            return JSONResponse(status_code=423, content={"error": "Share link is permanently locked"})

        # Validate password
        if not verify_password(password, share_row["password_hash"]):
            updated = increment_share_failure(conn, share_row["id"])
            remaining = max(0, updated["max_failed_attempts"] - updated["failed_attempts"])
            if share_attempt_limit_reached(updated):
                set_share_blocked_until(conn, share_row["id"], datetime.now(timezone.utc) + timedelta(minutes=30))
            log_download(conn, file_id=share_row["file_id"], user_id=None, share_link_id=share_row["id"],
                         success=False, reason="invalid share password", ip_address=ip, user_agent=ua)
            record_event(
                event_type="intrusion",
                severity="critical" if remaining == 0 else "high",
                action="share_password_failed",
                status="failed",
                message=f"Wrong share password — {remaining} attempts remaining",
                actor_user_id=None, actor_email=None, request=request,
                file_id=share_row["file_id"],
                metadata={"share_id": share_row["id"], "failed_attempts": updated["failed_attempts"], "ip": ip},
            )
            if remaining == 0:
                return JSONResponse(status_code=423, content={
                    "error": "Too many failed attempts. Link is now temporarily blocked for 30 minutes."
                })
            return JSONResponse(status_code=401, content={
                "error": f"Incorrect password. {remaining} attempt(s) remaining."
            })

        # Password correct — serve the file
        file_row = get_file_by_id(conn, share_row["file_id"])
        if not file_row or file_row["is_deleted"]:
            return JSONResponse(status_code=404, content={"error": "File not found"})
        if is_expired(file_row["expires_at"]):
            return JSONResponse(status_code=410, content={"error": "File has expired"})
        if file_is_download_limited(file_row):
            return JSONResponse(status_code=410, content={"error": "Download limit reached"})

        encrypted_blob = open(file_row["storage_path"], "rb").read()
        plaintext = decrypt_bytes(
            encrypted_blob, file_row["file_nonce"], file_row["encrypted_key"],
            file_row["key_nonce"], get_settings().master_key,
        )
        mark_download(conn, file_row["id"])
        touch_share(conn, share_row["id"])
        log_download(conn, file_id=file_row["id"], user_id=None, share_link_id=share_row["id"],
                     success=True, reason="api share download", ip_address=ip, user_agent=ua)

    logger.info("api_share_download share_id=%s file_id=%s ip=%s", share_row["id"], file_row["id"], ip)
    record_event(
        event_type="file_access", severity="medium", action="share_download", status="success",
        message="File downloaded via API share link",
        actor_user_id=None, actor_email=None, request=request,
        file_id=file_row["id"], file_name=file_row["original_name"],
        metadata={"share_id": share_row["id"], "ip": ip},
    )
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=file_row["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'},
    )

