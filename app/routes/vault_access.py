from __future__ import annotations

import io
from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from ..config import get_settings
from ..database import get_db
from ..security import hash_token, is_expired
from ..services.access_requests import (
    approve_access_request,
    consume_grant_token,
    create_access_request,
    get_access_request_for_owner,
    list_owner_access_requests,
    reject_access_request,
)
from ..services.crypto import decrypt_bytes
from ..services.dam import record_event
from ..services.files import file_is_download_limited, get_file_by_id, get_file_for_user, get_file_owner_email, log_download, mark_download
from ..services.notifications import send_security_alert
from ..deps import require_current_user, require_roles

router = APIRouter(prefix="/vault", tags=["vault-access"])

@router.post("/files/{file_id}/request-access")
def request_access(
    file_id: int,
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    purpose: str = Form(...),
):
    if not name.strip() or not purpose.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name and purpose are required")

    actor_id = None
    actor_email = None
    try:
        actor = require_current_user(request)
        actor_id = actor["id"]
        actor_email = actor["email"]
    except HTTPException:
        pass

    with get_db() as conn:
        file_row = get_file_by_id(conn, file_id)
        if not file_row or file_row["is_deleted"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        if actor_id is not None and file_row["owner_id"] == actor_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner does not need access request")

        req_row = create_access_request(
            conn, file_id=file_id, owner_id=file_row["owner_id"],
            requester_user_id=actor_id, requester_name=name,
            requester_email=email, purpose=purpose,
        )

    return {"request_id": req_row["id"], "status": req_row["status"]}

@router.get("/access-requests")
def list_requests(request: Request):
    owner = require_roles(request, {"OWNER", "ADMIN"})
    with get_db() as conn:
        rows = list_owner_access_requests(conn, owner["id"])
    return {
        "requests": [
            {
                "id": row["id"],
                "file_id": row["file_id"],
                "file_name": row["original_name"],
                "requester_name": row["requester_name"],
                "requester_email": row["requester_email"],
                "purpose": row["purpose"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }

@router.post("/access-requests/{request_id}/approve")
def approve_request(
    request_id: int,
    request: Request,
    expires_minutes: int = Form(60),
    max_uses: int = Form(1),
):
    owner = require_roles(request, {"OWNER", "ADMIN"})
    with get_db() as conn:
        target = get_access_request_for_owner(conn, request_id, owner["id"])
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
        grant, token = approve_access_request(
            conn, request_id=request_id, reviewer_id=owner["id"],
            expires_minutes=expires_minutes, max_uses=max_uses,
        )

    return {
        "request_id": request_id,
        "grant_token": token,
        "download_url": f"/vault/token-download?token={token}&email={grant['granted_to_email']}",
    }

@router.get("/token-download")
def token_download(token: str, email: str, request: Request):
    with get_db() as conn:
        grant = consume_grant_token(conn, token_hash=hash_token(token), requester_email=email)
        if not grant:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token or email")

        if is_expired(grant["file_expires_at"]) or file_is_download_limited(grant):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="File unavailable")

        from ..services.files import get_file_blob
        encrypted_blob = get_file_blob(grant["storage_path"])
        plaintext = decrypt_bytes(
            encrypted_blob, grant["file_nonce"], grant["encrypted_key"],
            grant["key_nonce"], get_settings().master_key,
        )
        mark_download(conn, grant["file_row_id"])

    return StreamingResponse(
        io.BytesIO(plaintext), media_type=grant["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{grant["original_name"]}"'},
    )
