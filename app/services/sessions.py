from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import now_utc


def create_session(
    conn,
    user_id: int,
    ip_address: str | None,
    user_agent: str | None,
    device_name: str | None = None,
) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    settings = get_settings()
    created_at = now_utc()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=settings.session_max_age_hours)).isoformat()

    conn.execute(
        """
        INSERT INTO user_sessions
        (user_id, session_token_hash, ip_address, user_agent, device_name, is_active, created_at, last_activity_at, expires_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (user_id, token_hash, ip_address, user_agent, device_name or "unknown", created_at, created_at, expires_at),
    )
    return token, token_hash


def verify_session(conn, user_id: int, session_token_hash: str) -> bool:
    row = conn.execute(
        """
        SELECT * FROM user_sessions
        WHERE user_id = ? AND session_token_hash = ? AND is_active = 1
        """,
        (user_id, session_token_hash),
    ).fetchone()
    if not row:
        return False

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        conn.execute(
            "UPDATE user_sessions SET is_active = 0 WHERE session_token_hash = ?",
            (session_token_hash,),
        )
        return False

    conn.execute(
        "UPDATE user_sessions SET last_activity_at = ? WHERE session_token_hash = ?",
        (now_utc(), session_token_hash),
    )
    return True


def list_user_sessions(conn, user_id: int) -> list:
    rows = conn.execute(
        """
        SELECT id, session_token_hash, ip_address, user_agent, device_name, is_active, created_at, last_activity_at, expires_at
        FROM user_sessions
        WHERE user_id = ? AND is_active = 1
        ORDER BY last_activity_at DESC
        """,
        (user_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def logout_session(conn, session_token_hash: str) -> None:
    conn.execute(
        "UPDATE user_sessions SET is_active = 0 WHERE session_token_hash = ?",
        (session_token_hash,),
    )


def logout_all_sessions(conn, user_id: int, except_token_hash: str | None = None) -> int:
    if except_token_hash:
        count = conn.execute(
            "UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND session_token_hash != ?",
            (user_id, except_token_hash),
        ).rowcount
    else:
        count = conn.execute(
            "UPDATE user_sessions SET is_active = 0 WHERE user_id = ?",
            (user_id,),
        ).rowcount
    return count


def cleanup_expired_sessions(conn) -> int:
    return conn.execute(
        "UPDATE user_sessions SET is_active = 0 WHERE expires_at < ?",
        (now_utc(),),
    ).rowcount
