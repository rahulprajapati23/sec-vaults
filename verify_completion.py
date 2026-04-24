from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

# Isolated verification database
os.environ["DATABASE_PATH"] = "./data/test-verify.db"
os.environ["KEYCLOAK_ENABLED"] = "false"

from app.database import get_db, init_db
from app.main import app
from app.security import hash_password


def ensure_tables(conn: sqlite3.Connection, required: list[str]) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    existing = {r[0] for r in rows}
    return [t for t in required if t not in existing]


def run() -> int:
    init_db()

    required_tables = [
        "vault_access_requests",
        "vault_access_grants",
        "dam_events",
        "login_attempt_logs",
        "auth_identities",
    ]

    failures: list[str] = []

    with get_db() as conn:
        missing = ensure_tables(conn, required_tables)
        if missing:
            failures.append(f"Missing tables: {missing}")

        # reset relevant tables for deterministic checks
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM login_attempt_logs")
        conn.execute("DELETE FROM auth_identities")
        conn.execute("DELETE FROM login_rate_limits")
        conn.execute("DELETE FROM dam_events")

        conn.execute(
            "INSERT INTO users (email, password_hash, created_at, role, is_active) VALUES (?, ?, datetime('now'), ?, 1)",
            ("verify@example.com", hash_password("CorrectPass!123"), "owner"),
        )

    client = TestClient(app)

    # 1) Keycloak IAM endpoint mounted
    r = client.get("/iam/status")
    if r.status_code != 200:
        failures.append(f"/iam/status status={r.status_code}")

    # 2) Keycloak register strong password policy check
    r = client.post(
        "/iam/register",
        data={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "weakpass",
            "role": "REQUESTER",
        },
    )
    if r.status_code != 400:
        failures.append(f"/iam/register weak password expected 400 got {r.status_code}")

    # 3) Brute-force: 3 failed attempts in configured window => locked
    statuses = []
    for _ in range(3):
        rr = client.post(
            "/auth/login",
            data={"email": "verify@example.com", "password": "wrong-password"},
        )
        statuses.append(rr.status_code)

    if statuses[-1] != 423:
        failures.append(f"Brute-force lock not triggered on 3rd attempt, statuses={statuses}")

    # 4) Ensure brute-force event logged
    with get_db() as conn:
        bf = conn.execute(
            "SELECT COUNT(*) as c FROM dam_events WHERE action='brute_force_detected'"
        ).fetchone()[0]
    if bf < 1:
        failures.append("No brute_force_detected event found in dam_events")

    # 5) Ensure new vault endpoints appear in OpenAPI
    paths = app.openapi().get("paths", {})
    expected_paths = [
        "/vault/files/{file_id}/request-access",
        "/vault/access-requests",
        "/vault/access-requests/{request_id}/approve",
        "/vault/token-download",
    ]
    for p in expected_paths:
        if p not in paths:
            failures.append(f"Missing API path: {p}")

    # 6) Structured JSON app log validation (last line parse)
    log_file = Path("./logs/app.log")
    if log_file.exists() and log_file.stat().st_size > 0:
        last_line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
        try:
            obj = json.loads(last_line)
            if not isinstance(obj, dict) or "level" not in obj or "message" not in obj:
                failures.append("Log line is JSON but missing required fields")
        except Exception:
            failures.append("Last log line is not valid JSON")

    # 7) Deployment artifacts exist
    if not Path("./deploy/postgres_schema.sql").exists():
        failures.append("Missing deploy/postgres_schema.sql")
    if not Path("./deploy/docker-compose.keycloak.yml").exists():
        failures.append("Missing deploy/docker-compose.keycloak.yml")

    if failures:
        print("VERIFICATION_FAILED")
        for item in failures:
            print(f"- {item}")
        return 1

    print("VERIFICATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
