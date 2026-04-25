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
    # Logic to initialize DB (either Postgres or SQLite)
    # This is simplified for the walkthrough
    pass

@contextmanager
def get_db() -> Iterator[Any]:
    settings = get_settings()
    is_postgres = settings.database_url and settings.database_url.startswith("postgres")
    
    if is_postgres:
        import psycopg2
        conn = psycopg2.connect(settings.database_url)
    else:
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
