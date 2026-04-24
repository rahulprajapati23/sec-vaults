# Secure File Storage System

A small FastAPI application that supports registration, login, encrypted file uploads, access-controlled downloads, password-protected sharing links, expiry, and audit logging.

This project now includes an enterprise-style DAM layer inspired by Guardium:
- Structured file/system access monitoring
- Brute-force detection and blocking
- Tamper-evident audit trails (hash-chain + HMAC)
- Real-time streaming to a remote log server over TLS
- SMTP security alerting for suspicious access and exfiltration actions
- RBAC-protected audit query APIs

## Features
- Register and login with bcrypt password hashing
- JWT authentication stored in an HttpOnly cookie
- AES-GCM encryption for every uploaded file
- SQLite metadata storage
- Ownership-based authorization
- Password-protected share links
- Expiry by time or download count
- Login/upload/download/audit logging

## Project Structure

- `app/` backend application
- `app/templates/` server-rendered pages
- `data/` SQLite database and encrypted blobs created at runtime
- `logs/` application logs created at runtime

## Run

1. Create and activate a Python virtual environment.
2. Copy `.env.example` to `.env` and set `SECRET_KEY` and `MASTER_KEY`.
	- Optionally configure `LOG_STREAM_URL`, SMTP settings, and admin emails.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Start the server:

```bash
uvicorn app.main:app --reload
```

5. Open `http://127.0.0.1:8000`

## DAM Documentation
- Architecture, schema, endpoints, and security notes: `docs/dam_architecture.md`

## Keycloak + Vault Access Workflow
- IAM status: `GET /iam/status`
- Keycloak registration: `POST /iam/register`
- Keycloak login: `POST /iam/login`
- Access request submission: `POST /vault/files/{file_id}/request-access`
- Owner request inbox: `GET /vault/access-requests`
- Owner approve/reject: `POST /vault/access-requests/{request_id}/approve` and `POST /vault/access-requests/{request_id}/reject`
- One-time secure token download: `GET /vault/token-download?token=<token>&email=<requester_email>`

## Production Deployment Artifacts
- PostgreSQL schema: `deploy/postgres_schema.sql`
- Keycloak + PostgreSQL compose stack: `deploy/docker-compose.keycloak.yml`

## Security Notes
- Passwords are stored only as bcrypt hashes.
- Files are encrypted before being written to disk.
- The raw file contents are never stored in SQLite.
- Share tokens are hashed before being stored.
- File downloads are blocked after expiry, download limits, or repeated failed share-password attempts.
