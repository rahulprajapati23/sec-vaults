from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

from ..database import now_utc
from ..security import hash_token


def create_access_request(
    conn: sqlite3.Connection,
    *,
    file_id: int,
    owner_id: int,
    requester_user_id: int | None,
    requester_name: str,
    requester_email: str,
    purpose: str,
) -> sqlite3.Row:
    cur = conn.execute(
        """
        INSERT INTO vault_access_requests (
            file_id, owner_id, requester_user_id, requester_name, requester_email,
            purpose, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            file_id,
            owner_id,
            requester_user_id,
            requester_name.strip(),
            requester_email.strip().lower(),
            purpose.strip(),
            now_utc(),
        ),
    )
    return conn.execute("SELECT * FROM vault_access_requests WHERE id = ?", (cur.lastrowid,)).fetchone()


def list_owner_access_requests(conn: sqlite3.Connection, owner_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT ar.*, f.original_name
        FROM vault_access_requests ar
        JOIN files f ON f.id = ar.file_id
        WHERE ar.owner_id = ?
        ORDER BY ar.created_at DESC
        """,
        (owner_id,),
    ).fetchall()


def get_access_request_for_owner(conn: sqlite3.Connection, request_id: int, owner_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM vault_access_requests WHERE id = ? AND owner_id = ?",
        (request_id, owner_id),
    ).fetchone()


def reject_access_request(conn: sqlite3.Connection, *, request_id: int, reviewer_id: int, decision_note: str | None) -> None:
    conn.execute(
        """
        UPDATE vault_access_requests
        SET status = 'rejected', decision_note = ?, reviewed_at = ?, reviewed_by = ?
        WHERE id = ?
        """,
        (decision_note, now_utc(), reviewer_id, request_id),
    )


def approve_access_request(
    conn: sqlite3.Connection,
    *,
    request_id: int,
    reviewer_id: int,
    expires_minutes: int,
    max_uses: int,
) -> tuple[sqlite3.Row, str]:
    req = conn.execute("SELECT * FROM vault_access_requests WHERE id = ?", (request_id,)).fetchone()
    if not req:
        raise ValueError("request not found")

    raw_token = os.urandom(24).hex()
    token_hash = hash_token(raw_token)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)).isoformat()

    conn.execute(
        """
        UPDATE vault_access_requests
        SET status = 'approved', reviewed_at = ?, reviewed_by = ?
        WHERE id = ?
        """,
        (now_utc(), reviewer_id, request_id),
    )

    cur = conn.execute(
        """
        INSERT INTO vault_access_grants (
            request_id, file_id, owner_id, granted_to_email,
            token_hash, expires_at, max_uses, use_count, revoked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
        """,
        (
            request_id,
            req["file_id"],
            req["owner_id"],
            req["requester_email"],
            token_hash,
            expires_at,
            max(1, max_uses),
            now_utc(),
        ),
    )
    grant = conn.execute("SELECT * FROM vault_access_grants WHERE id = ?", (cur.lastrowid,)).fetchone()
    return grant, raw_token


def consume_grant_token(conn: sqlite3.Connection, *, token_hash: str, requester_email: str) -> sqlite3.Row | None:
    row = conn.execute(
        """
     SELECT g.*, f.owner_id, f.original_name, f.storage_path, f.mime_type, f.file_nonce, f.encrypted_key, f.key_nonce,
         f.id AS file_row_id, f.download_count, f.max_downloads, f.expires_at AS file_expires_at
        FROM vault_access_grants g
        JOIN files f ON f.id = g.file_id
        WHERE g.token_hash = ?
          AND g.granted_to_email = ?
          AND g.revoked = 0
        """,
        (token_hash, requester_email.strip().lower()),
    ).fetchone()
    if not row:
        return None

    now = datetime.now(timezone.utc)
    grant_exp = datetime.fromisoformat(row["expires_at"])
    file_exp = datetime.fromisoformat(row["file_expires_at"])
    if grant_exp.tzinfo is None:
        grant_exp = grant_exp.replace(tzinfo=timezone.utc)
    if file_exp.tzinfo is None:
        file_exp = file_exp.replace(tzinfo=timezone.utc)

    if now >= grant_exp or now >= file_exp:
        return None
    if row["use_count"] >= row["max_uses"]:
        return None

    conn.execute(
        "UPDATE vault_access_grants SET use_count = use_count + 1, used_at = ? WHERE id = ?",
        (now_utc(), row["id"]),
    )
    return row
