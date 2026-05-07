from __future__ import annotations
import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

def _parse_csv(value: str) -> tuple[str, ...]:
    if not value.strip():
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())

@dataclass(frozen=True)
class Settings:
    secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    master_key: bytes
    database_url: str
    database_path: Path
    storage_path: Path
    max_upload_mb: int
    log_level: str
    log_signing_key: str
    log_stream_url: str
    log_stream_verify_tls: bool
    log_stream_auth_token: str
    login_failure_threshold: int
    login_failure_window_minutes: int
    brute_force_threshold: int
    login_temp_block_minutes: int
    login_permanent_block_after: int
    login_rate_limit_per_minute: int
    smtp_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_sender: str
    smtp_starttls: bool
    email_provider: str
    sendgrid_api_key: str
    admin_alert_emails: tuple[str, ...]
    admin_emails: tuple[str, ...]
    geolocation_enabled: bool
    email_verification_enabled: bool
    mfa_enabled: bool
    mfa_expiry_minutes: int
    telegram_enabled: bool
    telegram_bot_token: str
    telegram_chat_ids: list[int]
    log_retention_days: int
    session_max_age_hours: int
    supabase_url: str
    supabase_anon_key: str
    use_supabase: bool
    keycloak_enabled: bool
    keycloak_server_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str
    keycloak_admin_client_id: str
    keycloak_admin_client_secret: str
    virustotal_api_key: str
    frontend_app_url: str
    cors_allow_origins: tuple[str, ...]
    cookie_secure: bool
    cookie_samesite: str

def _load_master_key(value: str, secret_key: str) -> bytes:
    raw_value = (value or "").strip()
    # Keep the app bootable when a template placeholder is accidentally deployed.
    if raw_value in {"your-32-byte-base64-encoded-key", "your-32-byte-base64-encoded-key-here"}:
        return hashlib.sha256(secret_key.encode("utf-8")).digest()

    # Accept urlsafe base64 values even if padding is omitted by the deploy UI.
    padded_value = raw_value + ("=" * (-len(raw_value) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded_value.encode("utf-8"))
    except Exception as exc:
        raise ValueError(
            "MASTER_KEY must be a urlsafe base64 encoded 32-byte key. "
            "Generate one with: python -c \"import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())\""
        ) from exc
    if len(decoded) != 32:
        raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
    return decoded

def _load_dotenv(root: Path) -> None:
    # Load both backend/.env and repo-root .env so local dev picks up shared secrets.
    for env_path in (root / ".env", root.parent / ".env"):
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

def _to_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

def _parse_int_list(value: str) -> list[int]:
    if not value.strip():
        return []
    try:
        return [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError:
        return []

def get_settings() -> Settings:
    root = Path(__file__).resolve().parents[1]
    _load_dotenv(root)
    secret_key = os.getenv("SECRET_KEY", "change-me")
    master_key_value = os.getenv("MASTER_KEY", "")
    if not master_key_value:
        raise ValueError("MASTER_KEY is required")

    return Settings(
        secret_key=secret_key,
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")),
        master_key=_load_master_key(master_key_value, secret_key),
        database_url=os.getenv("DATABASE_URL", "").strip(),
        database_path=(root / os.getenv("DATABASE_PATH", "data/app.db")).resolve(),
        storage_path=(root / os.getenv("STORAGE_PATH", "data/storage")).resolve(),
        max_upload_mb=int(os.getenv("MAX_UPLOAD_MB", "10")),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_signing_key=os.getenv("LOG_SIGNING_KEY", secret_key),
        log_stream_url=os.getenv("LOG_STREAM_URL", "").strip(),
        log_stream_verify_tls=_to_bool(os.getenv("LOG_STREAM_VERIFY_TLS", "true"), True),
        log_stream_auth_token=os.getenv("LOG_STREAM_AUTH_TOKEN", "").strip(),
        login_failure_threshold=int(os.getenv("LOGIN_FAILURE_THRESHOLD", "5")),
        login_failure_window_minutes=int(os.getenv("LOGIN_FAILURE_WINDOW_MINUTES", "5")),
        brute_force_threshold=int(os.getenv("BRUTE_FORCE_THRESHOLD", "3")),
        login_temp_block_minutes=int(os.getenv("LOGIN_TEMP_BLOCK_MINUTES", "15")),
        login_permanent_block_after=int(os.getenv("LOGIN_PERMANENT_BLOCK_AFTER", "4")),
        login_rate_limit_per_minute=int(os.getenv("LOGIN_RATE_LIMIT_PER_MINUTE", "30")),
        smtp_enabled=_to_bool(os.getenv("SMTP_ENABLED", "false"), False),
        smtp_host=os.getenv("SMTP_HOST", "").strip(),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER", "").strip(),
        smtp_password=os.getenv("SMTP_PASSWORD", "").strip().replace(" ", ""),
        smtp_sender=os.getenv("SMTP_SENDER", "").strip(),
        smtp_starttls=_to_bool(os.getenv("SMTP_STARTTLS", "true"), True),
        email_provider=os.getenv("EMAIL_PROVIDER", "sendgrid").strip().lower(),
        sendgrid_api_key=os.getenv("SENDGRID_API_KEY", "").strip(),
        admin_alert_emails=_parse_csv(os.getenv("ADMIN_ALERT_EMAILS", "")),
        admin_emails=tuple(email.lower() for email in _parse_csv(os.getenv("ADMIN_EMAILS", ""))),
        geolocation_enabled=_to_bool(os.getenv("GEOLOCATION_ENABLED", "false"), False),
        email_verification_enabled=_to_bool(os.getenv("EMAIL_VERIFICATION_ENABLED", "true"), True),
        mfa_enabled=_to_bool(os.getenv("MFA_ENABLED", "true"), True),
        mfa_expiry_minutes=int(os.getenv("MFA_EXPIRY_MINUTES", "5")),
        telegram_enabled=_to_bool(os.getenv("TELEGRAM_ENABLED", "false"), False),
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
        telegram_chat_ids=_parse_int_list(os.getenv("TELEGRAM_CHAT_IDS", "")),
        log_retention_days=int(os.getenv("LOG_RETENTION_DAYS", "90")),
        session_max_age_hours=int(os.getenv("SESSION_MAX_AGE_HOURS", "24")),
        supabase_url=os.getenv("SUPABASE_URL", "").strip(),
        supabase_anon_key=os.getenv("SUPABASE_ANON_KEY", "").strip(),
        use_supabase=_to_bool(os.getenv("USE_SUPABASE", "true"), True),
        keycloak_enabled=_to_bool(os.getenv("KEYCLOAK_ENABLED", "false"), False),
        keycloak_server_url=os.getenv("KEYCLOAK_SERVER_URL", "").strip(),
        keycloak_realm=os.getenv("KEYCLOAK_REALM", "master").strip(),
        keycloak_client_id=os.getenv("KEYCLOAK_CLIENT_ID", "").strip(),
        keycloak_client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET", "").strip(),
        keycloak_admin_client_id=os.getenv("KEYCLOAK_ADMIN_CLIENT_ID", "").strip(),
        keycloak_admin_client_secret=os.getenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "").strip(),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        frontend_app_url=os.getenv("FRONTEND_APP_URL", "http://localhost:5174").strip().rstrip("/"),
        cors_allow_origins=_parse_csv(os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")),
        cookie_secure=_to_bool(os.getenv("COOKIE_SECURE", "false"), False),
        cookie_samesite=os.getenv("COOKIE_SAMESITE", "lax").strip().lower(),
    )
