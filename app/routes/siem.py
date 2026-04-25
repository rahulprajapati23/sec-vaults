from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Dict, Any
from ..database import get_db
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from ..deps import require_current_user, require_admin_user

router = APIRouter(prefix="/siem", tags=["siem"])

@router.get("/incidents")
async def list_incidents(user=Depends(require_current_user)):
    if user["role"] not in ["owner", "admin", "ADMIN"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    with get_db() as conn:
        incidents = conn.execute(
            "SELECT * FROM siem_incidents ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        return [dict(i) for i in incidents]

@router.get("/incidents/{incident_id}/logs")
async def get_incident_logs(incident_id: str, user=Depends(require_current_user)):
    if user["role"] not in ["owner", "admin", "ADMIN"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    with get_db() as conn:
        logs = conn.execute(
            """
            SELECT d.* FROM dam_events d
            JOIN siem_incident_logs sil ON d.event_id = sil.log_event_id
            WHERE sil.incident_id = ?
            ORDER BY d.created_at DESC
            """, (incident_id,)
        ).fetchall()
        
        parsed_logs = []
        for l in logs:
            d = dict(l)
            if d.get("metadata_json"):
                d["metadata"] = json.loads(d["metadata_json"])
            parsed_logs.append(d)
        return parsed_logs

@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, payload: dict, user=Depends(require_current_user)):
    if user["role"] not in ["owner", "admin", "ADMIN"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    with get_db() as conn:
        conn.execute(
            """
            UPDATE siem_incidents 
            SET status = 'resolved', resolved_at = ?, resolution_notes = ?
            WHERE id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), payload.get("notes", ""), incident_id)
        )
    return {"status": "resolved"}

@router.post("/response/block-ip")
async def block_ip(payload: dict, user=Depends(require_current_user)):
    if user["role"] not in ["owner", "admin", "ADMIN"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP required")
        
    with get_db() as conn:
        row = conn.execute("SELECT * FROM auth_identities WHERE ip_address = ?", (ip,)).fetchone()
        blocked_until = (datetime.now(timezone.utc) + timedelta(hours=payload.get("duration_hours", 24))).isoformat()
        
        if row:
            conn.execute("UPDATE auth_identities SET lockout_level = 1, blocked_until = ? WHERE ip_address = ?", (blocked_until, ip))
        else:
            conn.execute("INSERT INTO auth_identities (ip_address, lockout_level, blocked_until) VALUES (?, 1, ?)", (ip, blocked_until))
            
    from .ws_alerts import broadcaster
    await broadcaster.broadcast({
        "type": "alert",
        "severity": "high",
        "action": "ip_blocked",
        "message": f"IP {ip} blocked by SIEM Response",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"status": "success", "blocked_ip": ip}
