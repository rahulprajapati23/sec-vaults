import sqlite3
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Any, Protocol, Union

from .config import get_settings

logger = logging.getLogger("secure_file_storage")

# Schema for SQLite
SQLITE_SCHEMA = """
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
    downloaded_at TEXT NOT NULL,
    ip_address TEXT,
    status TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip_address TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_rate_limits (
    ip_address TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT NOT NULL,
    blocked_until TEXT
);

CREATE TABLE IF NOT EXISTS auth_identities (
    ip_address TEXT PRIMARY KEY,
    lockout_level INTEGER NOT NULL DEFAULT 0,
    blocked_until TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0
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
    event_hash TEXT,
    signature TEXT,
    streamed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS siem_incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    owasp_vector TEXT,
    risk_score INTEGER,
    status TEXT NOT NULL,
    affected_resource TEXT,
    attacker_ip TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    resolution_notes TEXT
);

CREATE TABLE IF NOT EXISTS siem_incident_logs (
    incident_id TEXT NOT NULL,
    log_event_id TEXT NOT NULL,
    PRIMARY KEY (incident_id, log_event_id),
    FOREIGN KEY (incident_id) REFERENCES siem_incidents (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS log_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL, -- 'real_time' or 'scheduled'
    conditions_json TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

# Schema for PostgreSQL
POSTGRES_SCHEMA = SQLITE_SCHEMA.replace(
    "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"
).replace(
    "BLOB", "BYTEA"
).replace(
    "PRAGMA foreign_keys = ON;", ""
)

class PostgresWrapper:
    def __init__(self, conn):
        self.conn = conn
        self.cursor = conn.cursor()
    
    def execute(self, sql: str, parameters: tuple = ()):
        # Convert ? to %s for PostgreSQL
        sql = sql.replace("?", "%s")
        self.cursor.execute(sql, parameters)
        return self.cursor
        
    def executescript(self, sql: str):
        # Postgres doesn't have executescript, just run the whole thing
        self.cursor.execute(sql)
        
    def commit(self):
        self.conn.commit()
        
    def close(self):
        self.cursor.close()
        self.conn.close()

    def fetchone(self):
        return self.cursor.fetchone()
        
    def fetchall(self):
        return self.cursor.fetchall()

    @property
    def rowcount(self):
        return self.cursor.rowcount

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def init_db() -> None:
    settings = get_settings()
    if settings.database_url and settings.database_url.startswith("postgres"):
        import psycopg2
        conn_raw = psycopg2.connect(settings.database_url)
        conn = PostgresWrapper(conn_raw)
        # Execute each statement separated by ;
        for statement in POSTGRES_SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.commit()
        conn.close()
    else:
        ensure_parent(settings.database_path)
        with sqlite3.connect(settings.database_path) as conn:
            conn.executescript(SQLITE_SCHEMA)
            conn.commit()

@contextmanager
def get_db() -> Iterator[Any]:
    settings = get_settings()
    is_postgres = settings.database_url and settings.database_url.startswith("postgres")
    
    if is_postgres:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn_raw = psycopg2.connect(settings.database_url)
        conn = PostgresWrapper(conn_raw)
    else:
        ensure_parent(settings.database_path)
        conn = sqlite3.connect(settings.database_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
