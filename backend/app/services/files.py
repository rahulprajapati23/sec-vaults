from __future__ import annotations
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ..config import get_settings
import time
import httpx

from ..database import get_db


def perform_virustotal_scan(storage_path: str, file_id: int) -> str:
    """Upload file to VirusTotal v3 API, poll for result, update DB, and return status.
    Returns one of: 'clean', 'infected', 'error'.
    """
    settings = get_settings()
    api_key = settings.virustotal_api_key
    status = "error"
    if not api_key:
        return status

    try:
        # Local signature guard for common test-malware payloads (EICAR).
        with open(storage_path, "rb") as fh:
            sample = fh.read(8192)
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in sample:
                status = "infected"
                raise RuntimeError("EICAR signature detected")

        headers = {"x-apikey": api_key}
        with open(storage_path, "rb") as fh:
            files = {"file": (Path(storage_path).name, fh, "application/octet-stream")}
            with httpx.Client(timeout=60.0) as client:
                resp = client.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                analysis_id = data.get("data", {}).get("id")
                if not analysis_id:
                    status = "error"
                else:
                    # Poll for completion (short timeout)
                    completed = False
                    for _ in range(15):
                        time.sleep(2)
                        poll = client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=30.0)
                        poll.raise_for_status()
                        pj = poll.json()
                        attrs = pj.get("data", {}).get("attributes", {})
                        if attrs.get("status") == "completed":
                            completed = True
                            stats = attrs.get("stats", {})
                            malicious = int(stats.get("malicious", 0) or 0)
                            if malicious > 0:
                                status = "infected"
                            else:
                                status = "clean"
                            break
                    if not completed:
                        status = "error"
    except Exception:
        if status not in {"infected", "clean"}:
            status = "error"

    # Persist status to DB if possible
    try:
        with get_db() as conn:
            placeholder = "?" if conn.__class__.__module__.startswith("sqlite3") else "%s"
            conn.execute(
                f"UPDATE files SET virus_scan_status = {placeholder}, virus_scan_timestamp = {placeholder} WHERE id = {placeholder}",
                (status, datetime.now(timezone.utc).isoformat(), file_id),
            )
    except Exception:
        # best-effort persist; ignore failures here
        pass

    return status

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
