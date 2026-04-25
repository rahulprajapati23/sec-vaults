from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..config import get_settings
from ..database import now_utc
from ..security import hash_token, is_expired, sanitize_filename, to_iso



def create_user(conn: sqlite3.Connection, email: str, password_hash: str, role: str = "user") -> sqlite3.Row:
    created_at = now_utc()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, created_at, role) VALUES (?, ?, ?, ?)",
        (email.lower(), password_hash, created_at, role),
    )
    return conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()



def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()



def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_file_owner_email(conn: sqlite3.Connection, file_id: int) -> str | None:
    row = conn.execute(
        """
        SELECT u.email
        FROM files f
        JOIN users u ON u.id = f.owner_id
        WHERE f.id = ?
        """,
        (file_id,),
    ).fetchone()
    if not row:
        return None
    return row["email"]



def get_supabase_client():
    from supabase import create_client
    settings = get_settings()
    return create_client(settings.supabase_url, settings.supabase_anon_key)

def store_encrypted_file(
    conn: Any,
    *,
    owner_id: int,
    original_name: str,
    mime_type: str,
    size_bytes: int,
    encrypted_blob: bytes,
    key_nonce: bytes,
    encrypted_key: bytes,
    file_nonce: bytes,
    expiry_hours: int,
    max_downloads: int | None,
) -> Any:
    settings = get_settings()
    stored_name = f"file_{os.urandom(16).hex()}.bin"
    
    if settings.use_supabase and settings.supabase_url:
        # Upload to Supabase Storage
        try:
            client = get_supabase_client()
            # Ensure bucket exists (this might fail if already exists, so we ignore error)
            try:
                client.storage.create_bucket("vault", options={"public": False})
            except:
                pass
            
            client.storage.from_("vault").upload(
                path=stored_name,
                file=encrypted_blob,
                file_options={"content-type": "application/octet-stream"}
            )
            storage_path = f"supabase://vault/{stored_name}"
        except Exception as e:
            # Fallback to local if Supabase fails (optional, or just raise)
            print(f"Supabase upload failed: {e}")
            raise
    else:
        # Local storage fallback
        settings.storage_path.mkdir(parents=True, exist_ok=True)
        storage_path_local = settings.storage_path / stored_name
        with storage_path_local.open("wb") as handle:
            handle.write(encrypted_blob)
        storage_path = str(storage_path_local)

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=expiry_hours)
    cur = conn.execute(
        """
        INSERT INTO files (
            owner_id, original_name, stored_name, mime_type, size_bytes,
            key_nonce, encrypted_key, file_nonce, storage_path, created_at,
            expires_at, max_downloads, download_count, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
        """,
        (
            owner_id,
            sanitize_filename(original_name),
            stored_name,
            mime_type,
            size_bytes,
            key_nonce,
            encrypted_key,
            file_nonce,
            storage_path,
            created_at.isoformat(),
            expires_at.isoformat(),
            max_downloads,
        ),
    )
    # Get the ID (works for both SQLite and Postgres via our wrapper)
    last_id = cur.lastrowid if hasattr(cur, 'lastrowid') else None
    if not last_id and not isinstance(conn, sqlite3.Connection):
        # For Postgres, we might need to fetch the ID differently if lastrowid is missing
        # But our wrapper should handle it or we can query it
        pass

    return conn.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC LIMIT 1", (owner_id,)).fetchone()



def list_files_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM files WHERE owner_id = ? AND is_deleted = 0 ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()



def get_file_for_user(conn: sqlite3.Connection, file_id: int, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ? AND is_deleted = 0",
        (file_id, user_id),
    ).fetchone()



def get_file_by_id(conn: sqlite3.Connection, file_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()



def mark_download(conn: sqlite3.Connection, file_id: int) -> None:
    conn.execute("UPDATE files SET download_count = download_count + 1 WHERE id = ?", (file_id,))



def create_share_link(
    conn: sqlite3.Connection,
    *,
    file_id: int,
    password_hash: str,
    created_by: int,
    expires_hours: int,
) -> tuple[sqlite3.Row, str]:
    token = os.urandom(32).hex()
    token_hash = hash_token(token)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=expires_hours)
    cur = conn.execute(
        """
        INSERT INTO share_links (
            file_id, token_hash, password_hash, created_by, created_at, expires_at,
            max_failed_attempts, failed_attempts
        ) VALUES (?, ?, ?, ?, ?, ?, 5, 0)
        """,
        (file_id, token_hash, password_hash, created_by, created_at.isoformat(), expires_at.isoformat()),
    )
    row = conn.execute("SELECT * FROM share_links WHERE id = ?", (cur.lastrowid,)).fetchone()
    return row, token



def get_share_by_token_hash(conn: sqlite3.Connection, token_hash: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM share_links WHERE token_hash = ?", (token_hash,)).fetchone()



def increment_share_failure(conn: sqlite3.Connection, share_id: int) -> sqlite3.Row:
    conn.execute("UPDATE share_links SET failed_attempts = failed_attempts + 1 WHERE id = ?", (share_id,))
    return conn.execute("SELECT * FROM share_links WHERE id = ?", (share_id,)).fetchone()



def set_share_blocked_until(conn: sqlite3.Connection, share_id: int, blocked_until: datetime) -> None:
    conn.execute("UPDATE share_links SET blocked_until = ? WHERE id = ?", (blocked_until.isoformat(), share_id))



def touch_share(conn: sqlite3.Connection, share_id: int) -> None:
    conn.execute("UPDATE share_links SET last_accessed_at = ? WHERE id = ?", (now_utc(), share_id))



def log_download(
    conn: sqlite3.Connection,
    *,
    file_id: int,
    user_id: int | None,
    share_link_id: int | None,
    success: bool,
    reason: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO download_logs (
            file_id, user_id, share_link_id, success, reason, ip_address, user_agent, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            user_id,
            share_link_id,
            1 if success else 0,
            reason,
            ip_address,
            user_agent,
            now_utc(),
        ),
    )



def get_file_blob(storage_path: str) -> bytes:
    """Retrieve the encrypted blob from either Supabase or local disk."""
    if storage_path.startswith("supabase://"):
        parts = storage_path.replace("supabase://", "").split("/", 1)
        bucket, path = parts[0], parts[1]
        client = get_supabase_client()
        return client.storage.from_(bucket).download(path)
    else:
        with open(storage_path, "rb") as f:
            return f.read()

def remove_file_blob(storage_path: str) -> None:
    if storage_path.startswith("supabase://"):
        parts = storage_path.replace("supabase://", "").split("/", 1)
        bucket, path = parts[0], parts[1]
        try:
            client = get_supabase_client()
            client.storage.from_(bucket).remove([path])
        except:
            pass
    else:
        path = Path(storage_path)
        if path.exists():
            path.unlink()



def delete_expired_files(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        "SELECT * FROM files WHERE is_deleted = 0 AND expires_at <= ?",
        (now_utc(),),
    ).fetchall()
    deleted = 0
    for row in rows:
        remove_file_blob(row["storage_path"])
        conn.execute("UPDATE files SET is_deleted = 1 WHERE id = ?", (row["id"],))
        deleted += 1
    return deleted



def file_is_download_limited(file_row: sqlite3.Row) -> bool:
    limit = file_row["max_downloads"]
    return limit is not None and file_row["download_count"] >= limit



def share_is_blocked(share_row: sqlite3.Row) -> bool:
    blocked_until = share_row["blocked_until"]
    if not blocked_until:
        return False
    try:
        blocked_at = datetime.fromisoformat(blocked_until)
    except ValueError:
        return False
    if blocked_at.tzinfo is None:
        blocked_at = blocked_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < blocked_at



def share_attempt_limit_reached(share_row: sqlite3.Row) -> bool:
    return share_row["failed_attempts"] >= share_row["max_failed_attempts"]
