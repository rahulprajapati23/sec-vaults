from __future__ import annotations

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
    return success_response({
        "total_events": total_events,
        "high_risk_events": high_risk_events,
        "failed_logins": 0,
        "unauthorized_access": 0,
        "malware_detected": 0,
        "unique_actors": 0,
        "top_attacker_ips": [],
    })


@router.post("/reports/send/{report_type}")
def send_report(request: Request, report_type: str):
    require_admin_user(request)
    return success_response({"message": f"{report_type.title()} report queued"})
