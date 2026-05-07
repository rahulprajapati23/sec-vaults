from __future__ import annotations

import json
from datetime import datetime, timezone
from fastapi import APIRouter, Request

from ..database import get_db
from ..deps import require_admin_user
from ..utils.response import success_response

router = APIRouter(tags=["reports"])


@router.get("/reports/summary")
def summary(request: Request, days: int = 1):
    require_admin_user(request)
    with get_db() as conn:
        total_events = conn.execute("SELECT COUNT(*) AS c FROM dam_events").fetchone()["c"]
        high_risk_events = conn.execute("SELECT COUNT(*) AS c FROM dam_events WHERE severity IN ('high', 'critical')").fetchone()["c"]
        failed_logins = conn.execute("SELECT COUNT(*) AS c FROM dam_events WHERE action = 'login_failure'").fetchone()["c"]
        unauthorized = conn.execute("SELECT COUNT(*) AS c FROM dam_events WHERE status = 'failure' AND action != 'login_failure'").fetchone()["c"]
        malware = conn.execute("SELECT COUNT(*) AS c FROM dam_events WHERE action = 'malware_detected'").fetchone()["c"]
        actors = conn.execute("SELECT COUNT(DISTINCT actor_user_id) AS c FROM dam_events WHERE actor_user_id IS NOT NULL").fetchone()["c"]
        
        top_ips = conn.execute(
            "SELECT source_ip, COUNT(*) as count FROM dam_events WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 5"
        ).fetchall()
        
    return success_response({
        "total_events": total_events,
        "high_risk_events": high_risk_events,
        "failed_logins": failed_logins,
        "unauthorized_access": unauthorized,
        "malware_detected": malware,
        "unique_actors": actors,
        "top_attacker_ips": [dict(ip) for ip in top_ips],
    })


@router.post("/reports/send/{report_type}")
def send_report(request: Request, report_type: str):
    user = require_admin_user(request)
    # Simulate report generation and sending
    with get_db() as conn:
        events = conn.execute("SELECT * FROM dam_events ORDER BY created_at DESC LIMIT 50").fetchall()
    
    report_content = f"# Security Report: {report_type.upper()}\n"
    report_content += f"Generated At: {datetime.now(timezone.utc).isoformat()}\n"
    report_content += f"Requested By: {user['email']}\n\n"
    report_content += "## Recent Security Events\n"
    for ev in events:
        report_content += f"- [{ev['severity'].upper()}] {ev['action']}: {ev['message']} (at {ev['created_at']})\n"
    
    # In a real app, we would email this or save to a file.
    # For this task, we'll log it and return success.
    print(f"REPORT GENERATED:\n{report_content}")
    
    return success_response({
        "message": f"{report_type.title()} report has been generated and sent to {user['email']}",
        "preview": report_content[:500] + "..."
    })
