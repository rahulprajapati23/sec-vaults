from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import get_settings


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    device_id TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    key_nonce BLOB NOT NULL,
    encrypted_key BLOB NOT NULL,
    file_nonce BLOB NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS share_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_failed_attempts INTEGER NOT NULL DEFAULT 5,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    blocked_until TEXT,
    last_accessed_at TEXT,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    user_id INTEGER,
    share_link_id INTEGER,
    success INTEGER NOT NULL,
    reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (share_link_id) REFERENCES share_links (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS auth_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_type TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,
    lockout_level INTEGER NOT NULL DEFAULT 0,
    blocked_until TEXT,
    permanent_blocked INTEGER NOT NULL DEFAULT 0,
    last_failed_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(identity_type, identity_value)
);

CREATE TABLE IF NOT EXISTS login_attempt_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_value TEXT,
    email TEXT,
    ip_address TEXT,
    success INTEGER NOT NULL,
    reason TEXT,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    window_start TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dam_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_user_id INTEGER,
    actor_email TEXT,
    source_ip TEXT,
    device_id TEXT,
    geo_country TEXT,
    geo_city TEXT,
    file_id INTEGER,
    file_name TEXT,
    file_path TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    streamed INTEGER NOT NULL DEFAULT 0,
    stream_error TEXT,
    FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_dam_events_created_at ON dam_events (created_at);
CREATE INDEX IF NOT EXISTS idx_dam_events_actor_email ON dam_events (actor_email);
CREATE INDEX IF NOT EXISTS idx_dam_events_source_ip ON dam_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_dam_events_action ON dam_events (action);
CREATE INDEX IF NOT EXISTS idx_dam_events_file_id ON dam_events (file_id);

CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    verified_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mfa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    verified_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    device_name TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_activity_at TEXT,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activity_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    report_type TEXT NOT NULL,
    format TEXT NOT NULL,
    file_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS log_cleanup_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    retention_days INTEGER NOT NULL,
    rows_deleted INTEGER NOT NULL,
    table_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS otp_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications (user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_tokens_user_id ON mfa_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_activity_reports_user_id ON activity_reports (user_id);
CREATE INDEX IF NOT EXISTS idx_log_cleanup_runs_created_at ON log_cleanup_runs (created_at);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_email ON otp_tokens (email);

CREATE TABLE IF NOT EXISTS vault_access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    owner_id INTEGER NOT NULL,
    requester_user_id INTEGER,
    requester_name TEXT NOT NULL,
    requester_email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    decision_note TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (requester_user_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS vault_access_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    owner_id INTEGER NOT NULL,
    granted_to_email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY (request_id) REFERENCES vault_access_requests (id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_requests_owner ON vault_access_requests (owner_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_access_requests_file ON vault_access_requests (file_id, status);
CREATE INDEX IF NOT EXISTS idx_access_grants_file ON vault_access_grants (file_id, revoked, expires_at);
CREATE INDEX IF NOT EXISTS idx_access_grants_email ON vault_access_grants (granted_to_email, revoked);
"""



def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()



def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)



def init_db() -> None:
    settings = get_settings()
    ensure_parent(settings.database_path)
    with sqlite3.connect(settings.database_path) as conn:
        conn.executescript(SCHEMA)
        # Backward-compatible migration for older database files.
        cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "device_id" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN device_id TEXT")
        if "is_active" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        conn.commit()


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    settings = get_settings()
    ensure_parent(settings.database_path)
    conn = sqlite3.connect(settings.database_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
