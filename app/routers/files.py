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
            "scan_status": row["scan_status"] if "scan_status" in row.keys() else "clean",
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

    # Malware Scanning via VirusTotal
    settings = get_settings()
    if settings.virustotal_api_key:
        file_hash = hashlib.sha256(content).hexdigest()
        async with httpx.AsyncClient() as client:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                headers = {"x-apikey": settings.virustotal_api_key}
                vt_resp = await client.get(vt_url, headers=headers, timeout=5.0)
                if vt_resp.status_code == 200:
                    vt_data = vt_resp.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        record_event(
                            event_type="security",
                            severity="critical",
                            action="malware_detected",
                            status="blocked",
                            message="Malware detected by VirusTotal during upload",
                            actor_user_id=user["id"],
                            actor_email=user["email"],
                            request=request,
                            metadata={"file_name": original_name, "sha256": file_hash, "vt_stats": stats},
                        )
                        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Malware detected. Upload blocked.")
            except httpx.RequestError as e:
                logger.error(f"VirusTotal API request failed: {e}")

    payload = encrypt_bytes(content, settings.master_key)
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


@router.post("/api-upload")
async def api_upload_file(
    request: Request,
    file: UploadFile = File(...),
    expiry_hours: int = Form(24),
    max_downloads: int | None = Form(None),
):
    """JSON-returning upload endpoint for the React SPA (does not redirect)."""
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
            except httpx.RequestError as e:
                logger.error(f"VirusTotal API error: {e}")

    payload = encrypt_bytes(content, settings.master_key)
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
    record_event(
        event_type="file_access", severity="low", action="write", status="success",
        message="Encrypted file uploaded via API",
        actor_user_id=user["id"], actor_email=user["email"], request=request,
        file_id=record["id"], file_name=record["original_name"], file_path=record["storage_path"],
        metadata={"size_bytes": len(content), "mime_type": file.content_type},
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
                event_type="intrusion", severity="high", action="unauthorized_access",
                status="failed", message="User attempted to create share for non-owned file",
                actor_user_id=user["id"], actor_email=user["email"], request=request, file_id=file_id,
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        share_row, token = create_share_link(
            conn, file_id=file_id, password_hash=hash_password(password),
            created_by=user["id"], expires_hours=expires_hours,
        )

    # Build the share URL (frontend-accessible)
    share_path = f"/share/{token}"
    # Determine base URL from request headers (works behind proxies)
    forwarded_host = request.headers.get("x-forwarded-host")
    forwarded_proto = request.headers.get("x-forwarded-proto", "http")
    if forwarded_host:
        base_url = f"{forwarded_proto}://{forwarded_host}"
    else:
        base_url = f"{request.url.scheme}://{request.url.netloc}"
    full_url = f"{base_url}{share_path}"

    # Generate QR code as base64 PNG
    qr_base64: str | None = None
    try:
        import base64 as _b64
        import qrcode
        from qrcode.image.pure import PyPNGImage
        import io as _io
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=4)
        qr.add_data(full_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0f172a", back_color="#f8fafc")
        buf = _io.BytesIO()
        img.save(buf, format="PNG")
        qr_base64 = "data:image/png;base64," + _b64.b64encode(buf.getvalue()).decode()
    except ImportError:
        logger.warning("qrcode library not installed — QR generation skipped. Run: pip install 'qrcode[pil]'")
    except Exception as exc:
        logger.error("QR generation failed: %s", exc)

    logger.info("share_created user_id=%s file_id=%s share_id=%s", user["id"], file_id, share_row["id"])
    record_event(
        event_type="file_access", severity="low", action="share_create", status="success",
        message="Created password-protected share link",
        actor_user_id=user["id"], actor_email=user["email"], request=request,
        file_id=file_id, file_name=file_row["original_name"], file_path=file_row["storage_path"],
        metadata={"share_id": share_row["id"], "expires_at": share_row["expires_at"], "expires_hours": expires_hours},
    )
    return {
        "share_url": share_path,
        "full_url": full_url,
        "share_id": share_row["id"],
        "expires_at": share_row["expires_at"],
        "qr_code": qr_base64,
        "file_name": file_row["original_name"],
    }



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


@router.delete("/{file_id}")
def delete_file_api(request: Request, file_id: int):
    """JSON-compatible delete for the React SPA."""
    from ..main import require_current_user

    user = require_current_user(request)
    with get_db() as conn:
        file_row = get_file_for_user(conn, file_id, user["id"])
        if not file_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        remove_file_blob(file_row["storage_path"])
        conn.execute("UPDATE files SET is_deleted = 1 WHERE id = ?", (file_id,))
    record_event(
        event_type="file_access", severity="medium", action="delete",
        status="success", message="Owner deleted file via API",
        actor_user_id=user["id"], actor_email=user["email"],
        request=request, file_id=file_id, file_name=file_row["original_name"],
    )
    return {"success": True, "file_id": file_id}


@router.post("/api-upload")
async def upload_file_api(
    request: Request,
    file: UploadFile = File(...),
    expiry_hours: int = Form(24),
    max_downloads: int | None = Form(None),
):
    """JSON-compatible upload for the React SPA (returns JSON, not redirect)."""
    from ..main import require_current_user

    user = require_current_user(request)
    if expiry_hours < 1 or expiry_hours > 720:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expiry_hours must be between 1 and 720")

    original_name = file.filename or "upload.bin"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty uploads are not allowed")
    if len(content) > max_file_size_bytes():
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds maximum allowed size")

    scan_status = "clean"
    settings = get_settings()
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
                        record_event(event_type="security", severity="critical", action="malware_detected",
                                     status="blocked", message="Malware detected by VirusTotal",
                                     actor_user_id=user["id"], actor_email=user["email"], request=request,
                                     metadata={"file_name": original_name, "vt_stats": stats})
                        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="Malware detected. Upload blocked.")
            except httpx.RequestError as e:
                logger.error(f"VirusTotal API request failed: {e}")

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
    record_event(event_type="file_access", severity="low", action="write", status="success",
                 message="Encrypted file uploaded via API", actor_user_id=user["id"],
                 actor_email=user["email"], request=request, file_id=record["id"],
                 file_name=record["original_name"], metadata={"size_bytes": len(content), "scan_status": scan_status})
    return {
        "id": record["id"],
        "original_name": record["original_name"],
        "size_bytes": len(content),
        "scan_status": scan_status,
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
    }



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


@router.get("/system/admin-keys.pem")
def honeypot_trigger(request: Request):
    """
    Honeypot endpoint. Any access here is considered malicious intent.
    Logs a critical event.
    """
    from ..main import require_current_user
    try:
        user = require_current_user(request)
        user_id = user["id"]
        email = user["email"]
    except Exception:
        user_id = None
        email = None

    record_event(
        event_type="intrusion",
        severity="critical",
        action="honeypot_accessed",
        status="blocked",
        message="Malicious actor attempted to access honeypot file",
        actor_user_id=user_id,
        actor_email=email,
        request=request,
        metadata={"target": "/files/system/admin-keys.pem"},
    )
    # Simulate a delayed response or generic 404 to avoid tipping off the attacker
    import time
    time.sleep(2)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

