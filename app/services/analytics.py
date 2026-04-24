from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..database import now_utc


def get_dashboard_stats(conn) -> dict:
    now = now_utc()
    days_back_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    days_back_7d = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    total_users = conn.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1").fetchone()["count"]
    total_files = conn.execute("SELECT COUNT(*) as count FROM files WHERE is_deleted = 0").fetchone()["count"]
    total_events = conn.execute("SELECT COUNT(*) as count FROM dam_events").fetchone()["count"]

    events_24h = conn.execute(
        "SELECT COUNT(*) as count FROM dam_events WHERE created_at >= ?",
        (days_back_24h,),
    ).fetchone()["count"]

    failed_logins_24h = conn.execute(
        "SELECT COUNT(*) as count FROM login_attempt_logs WHERE success = 0 AND created_at >= ?",
        (days_back_24h,),
    ).fetchone()["count"]

    high_severity_events = conn.execute(
        "SELECT COUNT(*) as count FROM dam_events WHERE severity IN ('high', 'critical')"
    ).fetchone()["count"]

    recent_events = conn.execute(
        """
        SELECT event_id, event_type, severity, actor_email, action, created_at
        FROM dam_events
        ORDER BY created_at DESC
        LIMIT 10
        """
    ).fetchall()

    top_accessed_files = conn.execute(
        """
        SELECT f.id, f.original_name, COUNT(d.id) as download_count
        FROM files f
        LEFT JOIN download_logs d ON d.file_id = f.id AND d.success = 1
        WHERE f.is_deleted = 0
        GROUP BY f.id
        ORDER BY download_count DESC
        LIMIT 5
        """
    ).fetchall()

    return {
        "total_users": total_users,
        "total_files": total_files,
        "total_events": total_events,
        "events_24h": events_24h,
        "failed_logins_24h": failed_logins_24h,
        "high_severity_events": high_severity_events,
        "recent_events": [dict(row) for row in recent_events],
        "top_accessed_files": [dict(row) for row in top_accessed_files],
    }


def get_user_activity_summary(conn, user_id: int) -> dict:
    days_back_7d = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    file_uploads = conn.execute(
        "SELECT COUNT(*) as count FROM dam_events WHERE actor_user_id = ? AND action = 'write'",
        (user_id,),
    ).fetchone()["count"]

    file_downloads = conn.execute(
        "SELECT COUNT(*) as count FROM dam_events WHERE actor_user_id = ? AND action = 'download'",
        (user_id,),
    ).fetchone()["count"]

    file_shares = conn.execute(
        "SELECT COUNT(*) as count FROM dam_events WHERE actor_user_id = ? AND action = 'share_create'",
        (user_id,),
    ).fetchone()["count"]

    failed_logins_7d = conn.execute(
        "SELECT COUNT(*) as count FROM login_attempt_logs WHERE identity_value = (SELECT email FROM users WHERE id = ?) AND success = 0 AND created_at >= ?",
        (user_id, days_back_7d),
    ).fetchone()["count"]

    recent_access_from_ips = conn.execute(
        """
        SELECT DISTINCT source_ip, MAX(created_at) as last_access
        FROM dam_events
        WHERE actor_user_id = ?
        GROUP BY source_ip
        ORDER BY last_access DESC
        LIMIT 5
        """,
        (user_id,),
    ).fetchall()

    return {
        "file_uploads": file_uploads,
        "file_downloads": file_downloads,
        "file_shares": file_shares,
        "failed_logins_7d": failed_logins_7d,
        "recent_ips": [dict(row) for row in recent_access_from_ips],
    }
