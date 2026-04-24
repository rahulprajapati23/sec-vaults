# Enterprise DAM Architecture (Guardium-inspired)

## 1) Textual System Architecture Diagram

```text
[Clients / Browsers / API Consumers]
                |
                | HTTPS + JWT Cookie
                v
       [FastAPI Application Layer]
                |
                |-- Auth Router (register/login/logout, brute-force/rate-limit controls)
                |-- File Router (upload/read/download/delete/share)
                |-- Sharing Router (password-protected link access)
                |-- DAM Router (RBAC-protected event query and integrity check)
                |
                | Emits normalized DAM events
                v
        [DAM Event Service]
                |
                |-- enriches source context (IP, device id, user agent)
                |-- optional geo-IP lookup
                |-- computes hash-chain + HMAC signature
                |-- stores immutable structured event rows
                |-- pushes to in-memory queue
                v
          [Streaming Worker Thread]
                |
                |-- HTTPS/TLS POST to centralized log collector
                |-- tracks stream status / error in DB
                |-- sends SMTP security alerts for critical activities
                v
   [Central SIEM / Log Aggregator / SOC Pipeline]

[SQLite DB]
  |- users, files, share_links, download_logs
  |- auth_identities, login_attempt_logs, login_rate_limits
  |- dam_events (tamper-evident audit trail)

[Encrypted File Storage]
  |- AES-GCM encrypted blobs
```

## 2) DAM-Oriented Folder Structure

```text
app/
  config.py
  database.py
  main.py
  routers/
    auth.py
    files.py
    sharing.py
    dam.py
  services/
    audit.py
    dam.py
    intrusion.py
    alerts.py
    geo.py
    files.py
```

## 3) Database Schema Summary

### users
- id (PK)
- email (unique)
- password_hash
- created_at
- role (`user` / `admin` / `auditor`)
- device_id
- is_active

### files
- id (PK)
- owner_id (FK -> users)
- original_name, stored_name
- mime_type, size_bytes
- key_nonce, encrypted_key, file_nonce
- storage_path
- created_at, expires_at
- max_downloads, download_count
- is_deleted

### share_links
- id (PK)
- file_id (FK)
- token_hash (unique)
- password_hash
- created_by (FK)
- created_at, expires_at
- max_failed_attempts, failed_attempts
- blocked_until, last_accessed_at

### download_logs
- id (PK)
- file_id (FK)
- user_id (FK nullable)
- share_link_id (FK nullable)
- success, reason
- ip_address, user_agent
- created_at

### auth_identities
- id (PK)
- identity_type (`email`/`ip`)
- identity_value
- failed_count
- lockout_level
- blocked_until
- permanent_blocked
- last_failed_at, updated_at
- unique(identity_type, identity_value)

### login_attempt_logs
- id (PK)
- identity_value, email, ip_address
- success
- reason
- severity
- created_at

### login_rate_limits
- id (PK)
- ip_address (unique)
- window_start
- request_count
- updated_at

### dam_events (tamper-evident)
- id (PK)
- event_id (UUID, unique)
- event_type
- severity
- actor_user_id / actor_email
- source_ip, device_id
- geo_country, geo_city
- file_id, file_name, file_path
- action, status, message
- metadata_json
- created_at
- previous_hash
- event_hash
- signature (HMAC)
- streamed, stream_error

## 4) API Endpoints and Examples

### Auth
- POST /auth/register
- POST /auth/login
- POST /auth/logout
- GET /auth/me

#### Example: GET /auth/me response
```json
{
  "id": 1,
  "email": "alice@example.com",
  "created_at": "2026-04-24T09:23:11.100000+00:00",
  "role": "admin"
}
```

### File + Share Operations (event producing)
- GET /files
- POST /files/upload
- GET /files/{file_id}/download
- POST /files/{file_id}/delete
- POST /files/{file_id}/share
- GET /share/{token}
- POST /share/{token}

### DAM (RBAC-protected: admin/auditor)
- GET /dam/events
- GET /dam/events/{event_id}/integrity

#### Example: GET /dam/events?action=download&severity=medium
```json
{
  "count": 1,
  "events": [
    {
      "event_id": "fa838bee-0d78-4492-b16e-902dbe6ec988",
      "event_type": "file_access",
      "severity": "medium",
      "actor_email": "alice@example.com",
      "source_ip": "10.10.10.8",
      "device_id": "corp-laptop-221",
      "geo_country": "Germany",
      "geo_city": "Berlin",
      "file_id": 10,
      "file_name": "financial_q1.csv",
      "action": "download",
      "status": "success",
      "created_at": "2026-04-24T10:01:44.000000+00:00",
      "event_hash": "...",
      "signature": "...",
      "streamed": true
    }
  ]
}
```

#### Example: GET /dam/events/{event_id}/integrity
```json
{
  "ok": true,
  "event_id": "fa838bee-0d78-4492-b16e-902dbe6ec988",
  "expected_previous_hash": "...",
  "stored_previous_hash": "...",
  "expected_hash": "...",
  "stored_hash": "..."
}
```

## 5) Security Controls Implemented

- JWT-based authentication (HttpOnly cookie session token)
- RBAC for audit APIs (`admin` and `auditor` only)
- Brute-force protection:
  - failed-attempt counters by user and IP
  - temporary lockout
  - permanent lockout escalation
- Login endpoint rate limiting (per-IP per minute)
- Structured DAM JSON events with consistent fields
- Hash-chain integrity (`previous_hash -> event_hash`) + HMAC signature
- TLS enforced for remote stream destination (`https://` only)
- SMTP alerting for suspicious and exfiltration-like actions
- Optional geolocation enrichment for source IP
- Immutable audit behavior in API surface (no user delete/edit log endpoint)

## 6) Attack Vectors and Mitigations

### Credential stuffing and brute-force
- Mitigated by per-IP/per-email failure tracking, lockout, and rate limiting.

### Log tampering
- Mitigated by append-only event model, hash chain linking, HMAC signature, and integrity verification endpoint.

### MITM on log forwarding
- Mitigated by HTTPS-only remote stream URL and TLS verification toggle.

### Unauthorized file exfiltration
- Mitigated by ownership checks, share password validation, failed-attempt controls, and real-time alerts.

### Token/session theft
- Reduced risk with HttpOnly cookies; production should also set `secure=true` behind HTTPS and consider short-lived tokens with refresh rotation.

### Insider misuse
- Mitigated by actor-attributed audit trails, severity classification, and anomaly events.

## 7) Bonus Features Included

- Anomaly detection: flags unusual geography/time combinations for known users.
- Login rate limiting: per-IP rolling minute window.
- Log integrity verification endpoint: re-computes expected hashes/signature.
