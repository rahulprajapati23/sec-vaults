from __future__ import annotations
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ..config import get_settings

def get_user_by_email(conn, email: str):
    return conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()

def get_user_by_id(conn, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def list_files_for_user(conn, user_id: int):
    return conn.execute("SELECT * FROM files WHERE owner_id = ? AND is_deleted = 0", (user_id,)).fetchall()

def get_file_for_user(conn, file_id: int, user_id: int):
    return conn.execute("SELECT * FROM files WHERE id = ? AND owner_id = ? AND is_deleted = 0", (file_id, user_id)).fetchone()

def mark_download(conn, file_id: int):
    conn.execute("UPDATE files SET download_count = download_count + 1 WHERE id = ?", (file_id,))

def get_file_blob(storage_path: str) -> bytes:
    with open(storage_path, "rb") as f:
        return f.read()

def remove_file_blob(storage_path: str):
    path = Path(storage_path)
    if path.exists(): path.unlink()
