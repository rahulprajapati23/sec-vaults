from __future__ import annotations
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any
import bcrypt
import jwt
from .config import get_settings

TOKEN_COOKIE_NAME = "access_token"
MAX_FAILED_SHARE_ATTEMPTS = 5
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    password_bytes = password.encode("utf-8")[:72]
    return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))

def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    settings = get_settings()
    expires = timedelta(minutes=expires_minutes or settings.access_token_expire_minutes)
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + expires,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)

def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def sanitize_filename(filename: str) -> str:
    cleaned = filename.strip().replace(" ", "_")
    cleaned = cleaned.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not cleaned or not FILENAME_PATTERN.match(cleaned):
        raise ValueError("Invalid filename")
    return cleaned

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def is_expired(expires_at: str) -> bool:
    return utc_now() >= parse_iso_datetime(expires_at)

def to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def max_file_size_bytes() -> int:
    return get_settings().max_upload_mb * 1024 * 1024
