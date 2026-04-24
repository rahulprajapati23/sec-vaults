"""
Enterprise-grade report generation service.
Generates daily/weekly HTML+CSV security reports and delivers them via email.
"""
from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from ..database import get_db, now_utc
from ..config import get_settings
from .notifications import send_email
from .audit import get_logger

logger = get_logger()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _period_range(days_back: int) -> tuple[str, str]:
    """Return (start_iso, end_iso) for the past N days."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days_back)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), now.isoformat()


def _query_events(conn, start: str, end: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT event_id, event_type, severity, actor_email, source_ip,
               geo_country, geo_city, file_name, action, status, message,
               metadata_json, created_at
        FROM dam_events
        WHERE created_at >= ? AND created_at <= ?
        ORDER BY created_at DESC
        """,
        (start, end),
    ).fetchall()
    return [dict(r) for r in rows]


# ─── Summary Builder ─────────────────────────────────────────────────────────

def build_report_summary(events: list[dict]) -> dict[str, Any]:
    """Compute all statistics from a list of DAM events."""
    total = len(events)
    by_severity: Counter = Counter(e["severity"] for e in events)
    by_action: Counter = Counter(e["action"] for e in events)
    by_type: Counter = Counter(e["event_type"] for e in events)

    failed_logins = [e for e in events if e["action"] in ("login_failed", "login_failure", "brute_force_detected")]
    unauthorized = [e for e in events if e["action"] == "unauthorized_access"]
    malware = [e for e in events if "malware" in e.get("action", "") or "infected" in e.get("status", "")]
    high_risk = [e for e in events if e["severity"] in ("high", "critical")]

    # Top attackers by IP
    attacker_ips: Counter = Counter(e["source_ip"] for e in failed_logins if e["source_ip"])
    top_attacker_ips = attacker_ips.most_common(5)

    # Unique users
    unique_actors = set(e["actor_email"] for e in events if e["actor_email"])

    return {
        "total_events": total,
        "by_severity": dict(by_severity),
        "by_action": dict(by_action.most_common(10)),
        "by_type": dict(by_type),
        "failed_logins": len(failed_logins),
        "unauthorized_access": len(unauthorized),
        "malware_detected": len(malware),
        "high_risk_events": len(high_risk),
        "top_attacker_ips": top_attacker_ips,
        "unique_actors": len(unique_actors),
        "recent_high_risk": high_risk[:5],
    }


# ─── CSV export ──────────────────────────────────────────────────────────────

def events_to_csv(events: list[dict]) -> str:
    """Serialize events list to CSV string for email attachment."""
    output = io.StringIO()
    if not events:
        return "No events in this period.\n"
    writer = csv.DictWriter(output, fieldnames=[
        "event_id", "event_type", "severity", "actor_email", "source_ip",
        "geo_country", "geo_city", "file_name", "action", "status", "message", "created_at"
    ], extrasaction="ignore")
    writer.writeheader()
    writer.writerows(events)
    return output.getvalue()


# ─── HTML Email Template ─────────────────────────────────────────────────────

def _severity_color(sev: str) -> str:
    return {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#3b82f6"}.get(sev, "#64748b")


def build_report_html(period_label: str, start: str, end: str, summary: dict, events: list[dict]) -> str:
    sev_rows = "".join(
        f'<tr><td style="padding:6px 12px;color:#94a3b8;font-size:13px">{s.upper()}</td>'
        f'<td style="padding:6px 12px;color:{_severity_color(s)};font-weight:700;font-size:13px;font-family:monospace">{c}</td></tr>'
        for s, c in sorted(summary["by_severity"].items(), key=lambda x: x[1], reverse=True)
    )

    attacker_rows = "".join(
        f'<tr><td style="padding:5px 10px;color:#94a3b8;font-size:12px;font-family:monospace">{ip}</td>'
        f'<td style="padding:5px 10px;color:#f97316;font-weight:700;font-size:12px">{count}×</td></tr>'
        for ip, count in summary["top_attacker_ips"]
    ) or '<tr><td colspan="2" style="padding:8px;color:#475569;font-size:12px">None</td></tr>'

    recent_rows = "".join(
        f'<tr>'
        f'<td style="padding:6px 10px;color:#64748b;font-size:11px;font-family:monospace">'
        f'{e["created_at"][:19] if e.get("created_at") else ""}</td>'
        f'<td style="padding:6px 10px"><span style="background:{_severity_color(e["severity"])}22;'
        f'color:{_severity_color(e["severity"])};padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:700">'
        f'{e["severity"].upper()}</span></td>'
        f'<td style="padding:6px 10px;color:#e2e8f0;font-size:12px">{e.get("action","").replace("_"," ")}</td>'
        f'<td style="padding:6px 10px;color:#94a3b8;font-size:11px">{e.get("actor_email") or "—"}</td>'
        f'</tr>'
        for e in summary.get("recent_high_risk", [])
    ) or '<tr><td colspan="4" style="padding:8px;color:#475569;font-size:12px">No high-risk events</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SecureVault {period_label} Report</title></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif">
  <div style="max-width:680px;margin:0 auto;padding:32px 16px">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid #1e293b;border-radius:16px;padding:28px;margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
        <div style="width:44px;height:44px;background:#2563eb;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px">🛡️</div>
        <div>
          <div style="color:#ffffff;font-size:18px;font-weight:700">SecureVault</div>
          <div style="color:#64748b;font-size:12px">Security Operations Center</div>
        </div>
      </div>
      <h1 style="color:#ffffff;font-size:22px;margin:0 0 6px">{period_label} Security Report</h1>
      <p style="color:#64748b;font-size:13px;margin:0">Period: {start[:10]} → {end[:10]}</p>
    </div>

    <!-- KPI Cards -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
      {_kpi_card("Total Events", summary["total_events"], "#3b82f6")}
      {_kpi_card("High Risk", summary["high_risk_events"], "#ef4444")}
      {_kpi_card("Failed Logins", summary["failed_logins"], "#f97316")}
      {_kpi_card("Malware Detected", summary["malware_detected"], "#a855f7")}
      {_kpi_card("Unauth Access", summary["unauthorized_access"], "#ef4444")}
      {_kpi_card("Unique Actors", summary["unique_actors"], "#22c55e")}
    </div>

    <!-- By Severity -->
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;margin-bottom:20px">
      <h2 style="color:#e2e8f0;font-size:14px;margin:0 0 12px;font-weight:700">Events by Severity</h2>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 12px;font-weight:600;text-transform:uppercase">Severity</th>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 12px;font-weight:600;text-transform:uppercase">Count</th>
        </tr></thead>
        <tbody>{sev_rows}</tbody>
      </table>
    </div>

    <!-- Top Attackers -->
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;margin-bottom:20px">
      <h2 style="color:#e2e8f0;font-size:14px;margin:0 0 12px;font-weight:700">⚠️ Top Suspicious IPs</h2>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">IP Address</th>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">Failed Attempts</th>
        </tr></thead>
        <tbody>{attacker_rows}</tbody>
      </table>
    </div>

    <!-- Recent High Risk -->
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;margin-bottom:20px">
      <h2 style="color:#e2e8f0;font-size:14px;margin:0 0 12px;font-weight:700">🔴 Recent High-Risk Events</h2>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">Time</th>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">Severity</th>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">Action</th>
          <th style="text-align:left;color:#475569;font-size:11px;padding:4px 10px;font-weight:600">Actor</th>
        </tr></thead>
        <tbody>{recent_rows}</tbody>
      </table>
    </div>

    <!-- Footer -->
    <div style="text-align:center;padding:20px 0 0">
      <p style="color:#334155;font-size:11px">
        This report was automatically generated by SecureVault SOC Engine.<br>
        Detailed logs are attached as CSV. Do not share this report externally.
      </p>
    </div>
  </div>
</body>
</html>"""


def _kpi_card(label: str, value: Any, color: str) -> str:
    return (
        f'<div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px;text-align:center">'
        f'<div style="color:{color};font-size:26px;font-weight:700;font-family:monospace">{value}</div>'
        f'<div style="color:#475569;font-size:11px;margin-top:4px;font-weight:600;text-transform:uppercase">{label}</div>'
        f'</div>'
    )


# ─── Report Delivery ─────────────────────────────────────────────────────────

def send_report_email(period_label: str, start: str, end: str) -> dict[str, Any]:
    """Generate and email a security report for the given period."""
    settings = get_settings()
    recipients = list(settings.admin_alert_emails) + list(settings.admin_emails)
    recipients = sorted(set(r for r in recipients if r))

    if not recipients:
        logger.warning("report_email_skipped reason=no_recipients")
        return {"sent": False, "reason": "no recipients configured"}

    with get_db() as conn:
        events = _query_events(conn, start, end)

    summary = build_report_summary(events)
    html = build_report_html(period_label, start, end, summary, events)
    csv_text = events_to_csv(events)

    plain = f"""SecureVault {period_label} Security Report
Period: {start[:10]} to {end[:10]}

SUMMARY
-------
Total Events    : {summary["total_events"]}
High Risk       : {summary["high_risk_events"]}
Failed Logins   : {summary["failed_logins"]}
Unauth Access   : {summary["unauthorized_access"]}
Malware         : {summary["malware_detected"]}
Unique Actors   : {summary["unique_actors"]}

TOP SUSPICIOUS IPs
------------------
{chr(10).join(f"  {ip}: {count} attempts" for ip, count in summary["top_attacker_ips"]) or "  None"}

Detailed logs attached as CSV.
"""
    sent = send_email(
        subject=f"[SecureVault] {period_label} Security Report — {start[:10]}",
        body=plain,
        html_body=html,
        recipients=recipients,
    )

    logger.info(
        "report_emailed period=%s events=%d recipients=%d sent=%s",
        period_label, summary["total_events"], len(recipients), sent,
    )

    return {
        "sent": sent,
        "period": period_label,
        "start": start,
        "end": end,
        "summary": summary,
        "recipients": recipients,
        "events_count": len(events),
    }


def send_daily_report() -> dict[str, Any]:
    start, end = _period_range(1)
    return send_report_email("Daily", start, end)


def send_weekly_report() -> dict[str, Any]:
    start, end = _period_range(7)
    return send_report_email("Weekly", start, end)


def get_report_summary_api(days: int = 1) -> dict[str, Any]:
    """Return report summary dict for the API (no email sent)."""
    start, end = _period_range(days)
    with get_db() as conn:
        events = _query_events(conn, start, end)
    summary = build_report_summary(events)
    return {"period_days": days, "start": start, "end": end, **summary}


# ─── Legacy export helpers (used by router endpoints) ────────────────────────

def generate_activity_csv(conn, user_id: int | None, start_date: str, end_date: str) -> str:
    """Generate a CSV report file for the given user/date range."""
    import csv as _csv
    from pathlib import Path as _Path

    settings = get_settings()
    report_dir = settings.database_path.parent.parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    filename = f"activity_{user_id or 'all'}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = report_dir / filename

    where_clause = "WHERE created_at >= ? AND created_at <= ?"
    params: list[Any] = [start_date, end_date]
    if user_id:
        where_clause += " AND actor_user_id = ?"
        params.append(user_id)

    rows = conn.execute(
        f"""
        SELECT event_id, event_type, severity, actor_email, source_ip, device_id,
               geo_country, geo_city, file_name, action, status, message, created_at
        FROM dam_events
        {where_clause}
        ORDER BY created_at DESC
        """,
        params,
    ).fetchall()

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = _csv.writer(f)
        writer.writerow([
            "Event ID", "Type", "Severity", "Actor Email", "Source IP", "Device ID",
            "Country", "City", "File Name", "Action", "Status", "Message", "Timestamp"
        ])
        for row in rows:
            writer.writerow(row)

    return str(filepath)


def generate_activity_json(conn, user_id: int | None, start_date: str, end_date: str) -> str:
    """Generate a JSON report file for the given user/date range."""
    settings = get_settings()
    report_dir = settings.database_path.parent.parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    filename = f"activity_{user_id or 'all'}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    filepath = report_dir / filename

    where_clause = "WHERE created_at >= ? AND created_at <= ?"
    params: list[Any] = [start_date, end_date]
    if user_id:
        where_clause += " AND actor_user_id = ?"
        params.append(user_id)

    rows = conn.execute(
        f"""
        SELECT event_id, event_type, severity, actor_user_id, actor_email, source_ip, device_id,
               geo_country, geo_city, file_id, file_name, action, status, message, metadata_json, created_at
        FROM dam_events
        {where_clause}
        ORDER BY created_at DESC
        """,
        params,
    ).fetchall()

    events = []
    for row in rows:
        events.append({
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
            "action": row["action"],
            "status": row["status"],
            "message": row["message"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "created_at": row["created_at"],
        })

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({"events": events, "generated_at": now_utc()}, f, indent=2)

    return str(filepath)


def store_report_metadata(conn, user_id: int | None, report_type: str, format_type: str, file_path: str) -> int:
    """Persist report metadata to the database."""
    from datetime import timedelta
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    cur = conn.execute(
        """
        INSERT INTO activity_reports (user_id, report_type, format, file_path, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, report_type, format_type, file_path, now_utc(), expires_at),
    )
    return cur.lastrowid

