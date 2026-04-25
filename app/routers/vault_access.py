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
        from ..deps import require_current_user

        actor = require_current_user(request)
        actor_id = actor["id"]
        actor_email = actor["email"]
    except HTTPException:
        actor = None

    with get_db() as conn:
        file_row = get_file_by_id(conn, file_id)
        if not file_row or file_row["is_deleted"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        if actor_id is not None and file_row["owner_id"] == actor_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner does not need access request")

        req_row = create_access_request(
            conn,
            file_id=file_id,
            owner_id=file_row["owner_id"],
            requester_user_id=actor_id,
            requester_name=name,
            requester_email=email,
            purpose=purpose,
        )

    owner_email = None
    with get_db() as conn:
        owner_email = get_file_owner_email(conn, file_id)

    if owner_email:
        send_security_alert(
            subject="[Vault] New access request",
            body=(
                f"request_id={req_row['id']}\n"
                f"file_id={file_id}\n"
                f"requester={name} <{email}>\n"
                f"purpose={purpose}\n"
                f"ip={(request.client.host if request.client else 'unknown')}"
            ),
            recipients=[owner_email],
            include_telegram=False,
        )

    record_event(
        event_type="access_request",
        severity="medium",
        action="request_access",
        status="success",
        message="Access request submitted",
        actor_user_id=actor_id,
        actor_email=actor_email or email,
        request=request,
        file_id=file_id,
        metadata={"request_id": req_row["id"], "requester_email": email},
    )
    return {"request_id": req_row["id"], "status": req_row["status"]}


@router.get("/access-requests")
def list_requests(request: Request):
    from ..deps import require_roles

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
    from ..deps import require_roles

    owner = require_roles(request, {"OWNER", "ADMIN"})
    if expires_minutes < 1 or expires_minutes > 24 * 60:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_minutes must be 1..1440")

    with get_db() as conn:
        target = get_access_request_for_owner(conn, request_id, owner["id"])
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
        if target["status"] != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request already handled")
        grant, token = approve_access_request(
            conn,
            request_id=request_id,
            reviewer_id=owner["id"],
            expires_minutes=expires_minutes,
            max_uses=max_uses,
        )

    record_event(
        event_type="access_request",
        severity="low",
        action="approve_access",
        status="success",
        message="Access request approved",
        actor_user_id=owner["id"],
        actor_email=owner["email"],
        request=request,
        file_id=grant["file_id"],
        metadata={"request_id": request_id, "grant_id": grant["id"]},
    )

    return {
        "request_id": request_id,
        "grant_token": token,
        "download_url": f"/vault/token-download?token={token}&email={grant['granted_to_email']}",
        "expires_at": grant["expires_at"],
        "max_uses": grant["max_uses"],
    }


@router.post("/access-requests/{request_id}/reject")
def reject_request(request_id: int, request: Request, note: str = Form("")):
    from ..deps import require_roles

    owner = require_roles(request, {"OWNER", "ADMIN"})
    with get_db() as conn:
        target = get_access_request_for_owner(conn, request_id, owner["id"])
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
        if target["status"] != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request already handled")
        reject_access_request(conn, request_id=request_id, reviewer_id=owner["id"], decision_note=note)

    record_event(
        event_type="access_request",
        severity="low",
        action="reject_access",
        status="success",
        message="Access request rejected",
        actor_user_id=owner["id"],
        actor_email=owner["email"],
        request=request,
        file_id=target["file_id"],
        metadata={"request_id": request_id},
    )
    return {"request_id": request_id, "status": "rejected"}


@router.get("/token-download")
def token_download(token: str, email: str, request: Request):
    if not token or not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token and email are required")

    with get_db() as conn:
        grant = consume_grant_token(conn, token_hash=hash_token(token), requester_email=email)
        if not grant:
            owner_email = None
            with get_db() as conn_owner:
                row = conn_owner.execute(
                    """
                    SELECT u.email
                    FROM vault_access_grants g
                    JOIN users u ON u.id = g.owner_id
                    WHERE g.token_hash = ?
                    """,
                    (hash_token(token),),
                ).fetchone()
                owner_email = row["email"] if row else None
            record_event(
                event_type="intrusion",
                severity="high",
                action="unauthorized_access",
                status="failed",
                message="Invalid or expired one-time token download attempt",
                actor_user_id=None,
                actor_email=email,
                request=request,
                metadata={"path": "/vault/token-download"},
            )
            send_security_alert(
                subject="[Vault] Unauthorized token download attempt",
                body=(
                    f"email={email}\n"
                    f"ip={(request.client.host if request.client else 'unknown')}\n"
                    f"time=immediate\n"
                    f"status=failed"
                ),
                recipients=([owner_email] if owner_email else []) + list(get_settings().admin_alert_emails),
                include_telegram=True,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token/email or token expired")

        if is_expired(grant["file_expires_at"]) or file_is_download_limited(grant):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="File unavailable")

        encrypted_blob = open(grant["storage_path"], "rb").read()
        plaintext = decrypt_bytes(
            encrypted_blob,
            grant["file_nonce"],
            grant["encrypted_key"],
            grant["key_nonce"],
            get_settings().master_key,
        )
        mark_download(conn, grant["file_row_id"])
        log_download(
            conn,
            file_id=grant["file_row_id"],
            user_id=None,
            share_link_id=None,
            success=True,
            reason="approved one-time token",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    record_event(
        event_type="file_access",
        severity="medium",
        action="download",
        status="success",
        message="File downloaded using one-time approved token",
        actor_user_id=None,
        actor_email=email,
        request=request,
        file_id=grant["file_row_id"],
        file_name=grant["original_name"],
        file_path=grant["storage_path"],
        metadata={"grant_id": grant["id"], "token_use": grant["use_count"] + 1},
    )

    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=grant["mime_type"],
        headers={"Content-Disposition": f'attachment; filename="{grant["original_name"]}"'},
    )

