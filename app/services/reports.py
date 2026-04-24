from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import get_settings
from ..database import now_utc


def generate_activity_csv(conn, user_id: int | None, start_date: str, end_date: str) -> str:
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
        writer = csv.writer(f)
        writer.writerow([
            "Event ID", "Type", "Severity", "Actor Email", "Source IP", "Device ID",
            "Country", "City", "File Name", "Action", "Status", "Message", "Timestamp"
        ])
        for row in rows:
            writer.writerow(row)

    return str(filepath)


def generate_activity_json(conn, user_id: int | None, start_date: str, end_date: str) -> str:
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
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    cur = conn.execute(
        """
        INSERT INTO activity_reports (user_id, report_type, format, file_path, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, report_type, format_type, file_path, now_utc(), expires_at),
    )
    return cur.lastrowid


def cleanup_expired_reports(conn) -> int:
    rows = conn.execute(
        "SELECT file_path FROM activity_reports WHERE expires_at < ?",
        (now_utc(),),
    ).fetchall()
    for row in rows:
        try:
            Path(row["file_path"]).unlink()
        except Exception:
            pass
    deleted = conn.execute(
        "DELETE FROM activity_reports WHERE expires_at < ?",
        (now_utc(),),
    ).rowcount
    return deleted
