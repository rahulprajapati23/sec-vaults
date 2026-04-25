from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Dict, Any
from ..database import get_db
import sqlite3
from datetime import datetime, timezone
from ..security import decode_token

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_token(token)
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return dict(user)

router = APIRouter(prefix="/siem", tags=["siem"])

@router.get("/incidents")
async def list_incidents(user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        incidents = conn.execute(
            "SELECT * FROM siem_incidents ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        return [dict(i) for i in incidents]

@router.get("/incidents/{incident_id}/logs")
async def get_incident_logs(incident_id: str, user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
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
            import json
            if d.get("metadata_json"):
                d["metadata"] = json.loads(d["metadata_json"])
            parsed_logs.append(d)
        return parsed_logs

@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, payload: dict, user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
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
async def block_ip(payload: dict, user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP required")
        
    with get_db() as conn:
        # Check if already blocked
        row = conn.execute("SELECT * FROM auth_identities WHERE ip_address = ?", (ip,)).fetchone()
        from datetime import timedelta
        blocked_until = (datetime.now(timezone.utc) + timedelta(hours=payload.get("duration_hours", 24))).isoformat()
        
        if row:
            conn.execute("UPDATE auth_identities SET lockout_level = 1, blocked_until = ? WHERE ip_address = ?", (blocked_until, ip))
        else:
            conn.execute("INSERT INTO auth_identities (ip_address, lockout_level, blocked_until) VALUES (?, 1, ?)", (ip, blocked_until))
            
    # Broadcast to SOC
    from .ws_alerts import broadcaster
    await broadcaster.broadcast({
        "type": "alert",
        "severity": "high",
        "action": "ip_blocked",
        "message": f"IP {ip} blocked by SIEM Response",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"status": "success", "blocked_ip": ip}

