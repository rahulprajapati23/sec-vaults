from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import now_utc


IDENTITY_EMAIL = "email"
IDENTITY_IP = "ip"


def _get_or_create_identity(conn, identity_type: str, identity_value: str):
    row = conn.execute(
        "SELECT * FROM auth_identities WHERE identity_type = ? AND identity_value = ?",
        (identity_type, identity_value),
    ).fetchone()
    if row:
        return row
    conn.execute(
        """
        INSERT INTO auth_identities (
            identity_type, identity_value, failed_count, lockout_level,
            blocked_until, permanent_blocked, last_failed_at, updated_at
        ) VALUES (?, ?, 0, 0, NULL, 0, NULL, ?)
        """,
        (identity_type, identity_value, now_utc()),
    )
    return conn.execute(
        "SELECT * FROM auth_identities WHERE identity_type = ? AND identity_value = ?",
        (identity_type, identity_value),
    ).fetchone()


def _is_temporarily_blocked(row) -> bool:
    if not row["blocked_until"]:
        return False
    blocked_until = datetime.fromisoformat(row["blocked_until"])
    if blocked_until.tzinfo is None:
        blocked_until = blocked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < blocked_until


def is_identity_blocked(conn, identity_type: str, identity_value: str) -> tuple[bool, str]:
    row = _get_or_create_identity(conn, identity_type, identity_value)
    if row["permanent_blocked"]:
        return (True, "permanent_block")
    if _is_temporarily_blocked(row):
        return (True, "temporary_block")
    return (False, "")


def reset_identity_failures(conn, identity_type: str, identity_value: str) -> None:
    conn.execute(
        """
        UPDATE auth_identities
        SET failed_count = 0, blocked_until = NULL, last_failed_at = NULL, updated_at = ?
        WHERE identity_type = ? AND identity_value = ?
        """,
        (now_utc(), identity_type, identity_value),
    )


def register_failed_auth(conn, identity_type: str, identity_value: str) -> tuple[bool, str]:
    settings = get_settings()
    row = _get_or_create_identity(conn, identity_type, identity_value)

    failed_count = int(row["failed_count"]) + 1
    lockout_level = int(row["lockout_level"])
    blocked_until = None
    permanent = int(row["permanent_blocked"])
    reason = "failed_attempt"

    if failed_count >= settings.login_failure_threshold:
        lockout_level += 1
        failed_count = 0
        if lockout_level >= settings.login_permanent_block_after:
            permanent = 1
            reason = "permanent_block"
        else:
            until = datetime.now(timezone.utc) + timedelta(minutes=settings.login_temp_block_minutes)
            blocked_until = until.isoformat()
            reason = "temporary_block"

    conn.execute(
        """
        UPDATE auth_identities
        SET failed_count = ?, lockout_level = ?, blocked_until = ?, permanent_blocked = ?,
            last_failed_at = ?, updated_at = ?
        WHERE identity_type = ? AND identity_value = ?
        """,
        (
            failed_count,
            lockout_level,
            blocked_until,
            permanent,
            now_utc(),
            now_utc(),
            identity_type,
            identity_value,
        ),
    )
    return (reason in {"temporary_block", "permanent_block"}, reason)


def register_login_attempt(
    conn,
    *,
    identity_value: str | None,
    email: str | None,
    ip_address: str | None,
    success: bool,
    reason: str,
    severity: str,
) -> None:
    conn.execute(
        """
        INSERT INTO login_attempt_logs (identity_value, email, ip_address, success, reason, severity, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            identity_value,
            email,
            ip_address,
            1 if success else 0,
            reason,
            severity,
            now_utc(),
        ),
    )


def is_login_rate_limited(conn, ip_address: str | None) -> tuple[bool, int]:
    if not ip_address:
        return (False, 0)
    settings = get_settings()
    now = datetime.now(timezone.utc)
    row = conn.execute("SELECT * FROM login_rate_limits WHERE ip_address = ?", (ip_address,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO login_rate_limits (ip_address, window_start, request_count, updated_at) VALUES (?, ?, 1, ?)",
            (ip_address, now.isoformat(), now_utc()),
        )
        return (False, 0)

    window_start = datetime.fromisoformat(row["window_start"])
    if window_start.tzinfo is None:
        window_start = window_start.replace(tzinfo=timezone.utc)

    if now - window_start > timedelta(minutes=1):
        conn.execute(
            "UPDATE login_rate_limits SET window_start = ?, request_count = 1, updated_at = ? WHERE ip_address = ?",
            (now.isoformat(), now_utc(), ip_address),
        )
        return (False, 0)

    request_count = int(row["request_count"]) + 1
    conn.execute(
        "UPDATE login_rate_limits SET request_count = ?, updated_at = ? WHERE ip_address = ?",
        (request_count, now_utc(), ip_address),
    )
    if request_count > settings.login_rate_limit_per_minute:
        return (True, 60)
    return (False, 0)
