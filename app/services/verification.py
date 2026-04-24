from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..database import now_utc


def generate_otp() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(6))


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def create_email_verification_token(conn, user_id: int, email: str) -> tuple[str, str]:
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    created_at = now_utc()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    conn.execute(
        """
        INSERT OR REPLACE INTO email_verifications
        (user_id, email, token_hash, is_verified, created_at, expires_at)
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (user_id, email, token_hash, created_at, expires_at),
    )
    return token, token_hash


def verify_email_token(conn, user_id: int, token_hash: str) -> bool:
    row = conn.execute(
        """
        SELECT * FROM email_verifications
        WHERE user_id = ? AND token_hash = ? AND is_verified = 0
        """,
        (user_id, token_hash),
    ).fetchone()
    if not row:
        return False

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        return False

    conn.execute(
        """
        UPDATE email_verifications
        SET is_verified = 1, verified_at = ?
        WHERE user_id = ?
        """,
        (now_utc(), user_id),
    )
    return True


def is_email_verified(conn, user_id: int) -> bool:
    row = conn.execute(
        "SELECT is_verified FROM email_verifications WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return bool(row and row["is_verified"])


def create_mfa_token(conn, user_id: int, method: str = "email") -> tuple[str, str]:
    otp = generate_otp()
    otp_hash = hash_otp(otp)
    created_at = now_utc()
    settings = get_settings()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_expiry_minutes)).isoformat()

    conn.execute(
        """
        INSERT INTO mfa_tokens (user_id, token_hash, method, is_verified, created_at, expires_at)
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (user_id, otp_hash, method, created_at, expires_at),
    )
    return otp, otp_hash


def verify_mfa_token(conn, user_id: int, otp_hash: str) -> bool:
    row = conn.execute(
        """
        SELECT * FROM mfa_tokens
        WHERE user_id = ? AND token_hash = ? AND is_verified = 0
        """,
        (user_id, otp_hash),
    ).fetchone()
    if not row:
        return False

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        return False

    conn.execute(
        """
        UPDATE mfa_tokens
        SET is_verified = 1, verified_at = ?
        WHERE user_id = ?
        """,
        (now_utc(), user_id),
    )
    return True


def cleanup_expired_tokens(conn) -> int:
    now = now_utc()
    deleted = 0

    deleted += conn.execute("DELETE FROM email_verifications WHERE expires_at < ?", (now,)).rowcount
    deleted += conn.execute("DELETE FROM mfa_tokens WHERE expires_at < ?", (now,)).rowcount
    return deleted
