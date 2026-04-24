from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request

from ..database import get_db
from ..services.dam import verify_event_integrity

router = APIRouter(prefix="/dam", tags=["dam"])


@router.get("/events")
def list_dam_events(
    request: Request,
    severity: str | None = None,
    action: str | None = None,
    actor_email: str | None = None,
    source_ip: str | None = None,
    file_id: int | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    from ..main import require_admin_user

    require_admin_user(request)

    filters = []
    values: list[object] = []
    if severity:
        filters.append("severity = ?")
        values.append(severity.lower())
    if action:
        filters.append("action = ?")
        values.append(action)
    if actor_email:
        filters.append("actor_email = ?")
        values.append(actor_email.lower())
    if source_ip:
        filters.append("source_ip = ?")
        values.append(source_ip)
    if file_id is not None:
        filters.append("file_id = ?")
        values.append(file_id)
    if status:
        filters.append("status = ?")
        values.append(status)

    where = ""
    if filters:
        where = "WHERE " + " AND ".join(filters)

    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT event_id, event_type, severity, actor_user_id, actor_email, source_ip,
                   device_id, geo_country, geo_city, file_id, file_name, file_path,
                   action, status, message, metadata_json, created_at,
                   previous_hash, event_hash, signature, streamed, stream_error
            FROM dam_events
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (*values, limit, offset),
        ).fetchall()

    events = []
    for row in rows:
        events.append(
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "actor_user_id": row["actor_user_id"],
                "actor_email": row["actor_email"],
                "source_ip": row["source_ip"],
                "device_id": row["device_id"],
                "geo_country": row["geo_country"],
                "geo_city": row["geo_city"],
                "file_id": row["file_id"],
                "file_name": row["file_name"],
                "file_path": row["file_path"],
                "action": row["action"],
                "status": row["status"],
                "message": row["message"],
                "metadata": json.loads(row["metadata_json"] or "{}"),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
                "signature": row["signature"],
                "streamed": bool(row["streamed"]),
                "stream_error": row["stream_error"],
            }
        )

    return {"count": len(events), "events": events}


@router.get("/events/{event_id}/integrity")
def check_integrity(event_id: str, request: Request):
    from ..main import require_admin_user

    require_admin_user(request)
    result = verify_event_integrity(event_id)
    if result.get("reason") == "event_not_found":
        raise HTTPException(status_code=404, detail="Event not found")
    return result
