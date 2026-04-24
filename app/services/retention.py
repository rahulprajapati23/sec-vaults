from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import now_utc


def run_data_retention_cleanup(conn) -> dict:
    settings = get_settings()
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=settings.log_retention_days)).isoformat()
    results = {}

    deleted = conn.execute(
        "DELETE FROM dam_events WHERE created_at < ?",
        (cutoff_date,),
    ).rowcount
    results["dam_events"] = deleted
    if deleted > 0:
        conn.execute(
            "INSERT INTO log_cleanup_runs (retention_days, rows_deleted, table_name, created_at) VALUES (?, ?, ?, ?)",
            (settings.log_retention_days, deleted, "dam_events", now_utc()),
        )

    deleted = conn.execute(
        "DELETE FROM login_attempt_logs WHERE created_at < ?",
        (cutoff_date,),
    ).rowcount
    results["login_attempt_logs"] = deleted
    if deleted > 0:
        conn.execute(
            "INSERT INTO log_cleanup_runs (retention_days, rows_deleted, table_name, created_at) VALUES (?, ?, ?, ?)",
            (settings.log_retention_days, deleted, "login_attempt_logs", now_utc()),
        )

    deleted = conn.execute(
        "DELETE FROM download_logs WHERE created_at < ?",
        (cutoff_date,),
    ).rowcount
    results["download_logs"] = deleted
    if deleted > 0:
        conn.execute(
            "INSERT INTO log_cleanup_runs (retention_days, rows_deleted, table_name, created_at) VALUES (?, ?, ?, ?)",
            (settings.log_retention_days, deleted, "download_logs", now_utc()),
        )

    deleted_sessions = conn.execute(
        "DELETE FROM user_sessions WHERE expires_at < ?",
        (now_utc(),),
    ).rowcount
    results["user_sessions"] = deleted_sessions

    deleted_reports = conn.execute(
        "DELETE FROM activity_reports WHERE expires_at < ?",
        (now_utc(),),
    ).rowcount
    results["activity_reports"] = deleted_reports

    return results
