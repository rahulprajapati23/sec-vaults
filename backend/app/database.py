import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Any
from .config import get_settings

logger = logging.getLogger("secure_file_storage")

# Simplified database.py for the backend/app structure
def init_db() -> None:
    settings = get_settings()
    if settings.database_url and settings.database_url.startswith("postgres"):
        try:
            import psycopg2
        except ModuleNotFoundError:
            pass
        else:
            try:
                with psycopg2.connect(settings.database_url) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS users (
                                id SERIAL PRIMARY KEY,
                                email TEXT NOT NULL UNIQUE,
                                password_hash TEXT NOT NULL,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                role TEXT NOT NULL DEFAULT 'user',
                                device_id TEXT,
                                is_active BOOLEAN NOT NULL DEFAULT TRUE
                            )
                        """)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS files (
                                id SERIAL PRIMARY KEY,
                                owner_id INTEGER NOT NULL,
                                original_name TEXT NOT NULL,
                                mime_type TEXT NOT NULL,
                                size_bytes BIGINT NOT NULL,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP WITH TIME ZONE,
                                max_downloads INTEGER,
                                download_count INTEGER NOT NULL DEFAULT 0,
                                is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
                                storage_path TEXT NOT NULL
                            )
                        """)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS share_links (
                                id SERIAL PRIMARY KEY,
                                token_hash TEXT NOT NULL UNIQUE,
                                file_id INTEGER NOT NULL,
                                password_hash TEXT NOT NULL,
                                created_by INTEGER NOT NULL,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP WITH TIME ZONE,
                                max_failed_attempts INTEGER NOT NULL DEFAULT 5,
                                failed_attempts INTEGER NOT NULL DEFAULT 0,
                                blocked_until TIMESTAMP WITH TIME ZONE,
                                last_accessed_at TIMESTAMP WITH TIME ZONE
                            )
                        """)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS dam_events (
                                id SERIAL PRIMARY KEY,
                                event_id TEXT NOT NULL UNIQUE,
                                event_type TEXT NOT NULL,
                                severity TEXT NOT NULL,
                                actor_user_id INTEGER,
                                actor_email TEXT,
                                source_ip TEXT,
                                action TEXT NOT NULL,
                                status TEXT NOT NULL,
                                message TEXT,
                                metadata_json TEXT,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                            )
                        """)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS siem_incidents (
                                id TEXT PRIMARY KEY,
                                title TEXT NOT NULL,
                                owasp_vector TEXT,
                                risk_score INTEGER,
                                status TEXT NOT NULL,
                                affected_resource TEXT,
                                attacker_ip TEXT,
                                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                resolved_at TIMESTAMP WITH TIME ZONE,
                                resolution_notes TEXT
                            )
                        """)
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS system_settings (
                                key TEXT PRIMARY KEY,
                                value TEXT NOT NULL
                            )
                        """)
                return
            except Exception:
                # Failed to reach Postgres DB — fall back to local SQLite initialization
                pass

    db_path = settings.database_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                role TEXT NOT NULL DEFAULT 'user',
                device_id TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_downloads INTEGER,
                download_count INTEGER NOT NULL DEFAULT 0,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                storage_path TEXT NOT NULL
            )
        """)
        # Ensure virus scan columns exist for files table (add if missing)
        try:
            existing = [r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()]
            if "virus_scan_status" not in existing:
                conn.execute("ALTER TABLE files ADD COLUMN virus_scan_status TEXT DEFAULT 'pending'")
            if "virus_scan_timestamp" not in existing:
                conn.execute("ALTER TABLE files ADD COLUMN virus_scan_timestamp TIMESTAMP NULL")
        except Exception:
            # best-effort; ignore migration errors
            pass
        conn.execute("""
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                file_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_failed_attempts INTEGER NOT NULL DEFAULT 5,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                blocked_until TIMESTAMP,
                last_accessed_at TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dam_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                actor_user_id INTEGER,
                actor_email TEXT,
                source_ip TEXT,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                metadata_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS siem_incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                owasp_vector TEXT,
                risk_score INTEGER,
                status TEXT NOT NULL,
                affected_resource TEXT,
                attacker_ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolution_notes TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()

@contextmanager
def get_db() -> Iterator[Any]:
    settings = get_settings()
    is_postgres = settings.database_url and settings.database_url.startswith("postgres")
    
    if is_postgres:
        try:
            import psycopg2
        except ModuleNotFoundError:
            is_postgres = False
        else:
            try:
                conn = psycopg2.connect(settings.database_url)
            except Exception:
                # Unable to connect to Postgres — fall back to SQLite
                is_postgres = False

    if not is_postgres:
        db_path = settings.database_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
