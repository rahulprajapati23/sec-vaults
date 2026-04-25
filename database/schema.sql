-- SecureVault Database Schema (PostgreSQL compatible)

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    role TEXT NOT NULL DEFAULT 'user',
    device_id TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    key_nonce BYTEA NOT NULL,
    encrypted_key BYTEA NOT NULL,
    file_nonce BYTEA NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS share_links (
    id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_failed_attempts INTEGER NOT NULL DEFAULT 5,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    blocked_until TIMESTAMP WITH TIME ZONE,
    last_accessed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS download_logs (
    id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    downloaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_logs (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    ip_address TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_rate_limits (
    ip_address TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS auth_identities (
    ip_address TEXT PRIMARY KEY,
    lockout_level INTEGER NOT NULL DEFAULT 0,
    blocked_until TIMESTAMP WITH TIME ZONE,
    risk_score INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dam_events (
    id SERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_hash TEXT,
    event_hash TEXT,
    signature TEXT,
    streamed BOOLEAN NOT NULL DEFAULT FALSE
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT
);

CREATE TABLE IF NOT EXISTS siem_incident_logs (
    incident_id TEXT NOT NULL REFERENCES siem_incidents(id) ON DELETE CASCADE,
    log_event_id TEXT NOT NULL,
    PRIMARY KEY (incident_id, log_event_id)
);

CREATE TABLE IF NOT EXISTS log_policies (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL, -- 'real_time' or 'scheduled'
    conditions_json TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
