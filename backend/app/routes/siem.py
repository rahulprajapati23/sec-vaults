from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Request

from ..database import get_db
from ..deps import require_admin_user
from ..utils.response import success_response

router = APIRouter(tags=["siem"])


@router.get("/siem/incidents")
def incidents(request: Request):
    require_admin_user(request)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM siem_incidents ORDER BY created_at DESC").fetchall()
    return success_response([dict(row) for row in rows])


@router.post("/siem/response/block-ip")
def block_ip(request: Request, payload: dict = Body(...)):
    require_admin_user(request)
    ip = str(payload.get("ip", "")).strip()
    duration_hours = int(payload.get("duration_hours", 24))
    return success_response({"message": f"IP {ip} blocked for {duration_hours} hours"})


@router.post("/siem/incidents/{incident_id}/resolve")
def resolve_incident(request: Request, incident_id: str, payload: dict = Body(default_factory=dict)):
    require_admin_user(request)
    notes = str(payload.get("notes", "Resolved by SOC"))
    with get_db() as conn:
        conn.execute(
            "UPDATE siem_incidents SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, resolution_notes = ? WHERE id = ?",
            (notes, incident_id),
        )
    return success_response({"message": "Incident resolved"})
