-- PostgreSQL schema for production deployment
-- Run with: psql -h <host> -U <user> -d <db> -f deploy/postgres_schema.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    keycloak_user_id UUID,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    role TEXT NOT NULL DEFAULT 'OWNER',
    device_id TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (role IN ('OWNER', 'REQUESTER', 'ADMIN'))
);

CREATE TABLE IF NOT EXISTS files (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    key_nonce BYTEA NOT NULL,
    encrypted_key BYTEA NOT NULL,
    file_nonce BYTEA NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_downloads INT,
    download_count INT NOT NULL DEFAULT 0,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS share_links (
    id BIGSERIAL PRIMARY KEY,
    file_id BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_by BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_failed_attempts INT NOT NULL DEFAULT 5,
    failed_attempts INT NOT NULL DEFAULT 0,
    blocked_until TIMESTAMPTZ,
    last_accessed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS login_attempt_logs (
    id BIGSERIAL PRIMARY KEY,
    identity_value TEXT,
    email TEXT,
    ip_address INET,
    success BOOLEAN NOT NULL,
    reason TEXT,
    severity TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_identities (
    id BIGSERIAL PRIMARY KEY,
    identity_type TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    failed_count INT NOT NULL DEFAULT 0,
    lockout_level INT NOT NULL DEFAULT 0,
    blocked_until TIMESTAMPTZ,
    permanent_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    last_failed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (identity_type, identity_value)
);

CREATE TABLE IF NOT EXISTS dam_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_email TEXT,
    source_ip INET,
    device_id TEXT,
    geo_country TEXT,
    geo_city TEXT,
    file_id BIGINT REFERENCES files(id) ON DELETE SET NULL,
    file_name TEXT,
    file_path TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    streamed BOOLEAN NOT NULL DEFAULT FALSE,
    stream_error TEXT
);

CREATE TABLE IF NOT EXISTS vault_access_requests (
    id BIGSERIAL PRIMARY KEY,
    file_id BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requester_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    requester_name TEXT NOT NULL,
    requester_email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    decision_note TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ,
    reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE TABLE IF NOT EXISTS vault_access_grants (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES vault_access_requests(id) ON DELETE CASCADE,
    file_id BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_to_email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INT NOT NULL DEFAULT 1,
    use_count INT NOT NULL DEFAULT 0,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_files_expiry ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_login_attempt_logs_email_time ON login_attempt_logs(email, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempt_logs_ip_time ON login_attempt_logs(ip_address, created_at);
CREATE INDEX IF NOT EXISTS idx_dam_events_created_at ON dam_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dam_events_action ON dam_events(action, severity);
CREATE INDEX IF NOT EXISTS idx_access_requests_owner ON vault_access_requests(owner_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_grants_token ON vault_access_grants(token_hash);
