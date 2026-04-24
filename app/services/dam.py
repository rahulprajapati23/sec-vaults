import asyncio
import hashlib
import hmac
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import Request

from ..config import get_settings
from ..database import get_db, now_utc
from .notifications import send_security_alert
from .audit import get_logger
from .geo import resolve_ip_geolocation

logger = get_logger()
_stream_queue: Optional[asyncio.Queue[dict[str, Any]]] = None
_worker_task: Optional[asyncio.Task] = None


ALERT_ACTIONS = {"unauthorized_access", "download", "share_download", "brute_force_detected"}


def _calculate_risk_score(*, severity: str, action: str, status: str, geo_country: str | None, actor_user_id: int | None) -> tuple[float, list[str]]:
    severity_base = {
        "low": 1.0,
        "medium": 3.0,
        "high": 6.0,
        "critical": 8.0,
    }.get(severity.lower(), 2.0)
    factors: list[str] = [f"severity:{severity.lower()}"]
    score = severity_base

    if status.lower() in {"failed", "blocked", "suspicious"}:
        score += 1.0
        factors.append(f"status:{status.lower()}")
    if action in {"unauthorized_access", "brute_force_detected"}:
        score += 2.0
        factors.append(f"action:{action}")
    if not actor_user_id:
        score += 0.5
        factors.append("anonymous_actor")
    if not geo_country:
        score += 0.5
        factors.append("unknown_geolocation")

    return min(score, 10.0), factors


def _hmac_sign(value: str) -> str:
    key = get_settings().log_signing_key.encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def extract_request_context(request: Request | None) -> dict[str, str | None]:
    if request is None:
        return {
            "ip": None,
            "device_id": None,
            "user_agent": None,
        }
    forwarded = request.headers.get("x-forwarded-for")
    ip_address = None
    if forwarded:
        ip_address = forwarded.split(",", 1)[0].strip()
    elif request.client:
        ip_address = request.client.host
    return {
        "ip": ip_address,
        "device_id": request.headers.get("x-device-id") or request.headers.get("x-client-id"),
        "user_agent": request.headers.get("user-agent"),
    }


def start_stream_worker() -> None:
    global _worker_task, _stream_queue
    if _stream_queue is None:
        _stream_queue = asyncio.Queue(maxsize=10000)
    if _worker_task is None:
        _worker_task = asyncio.create_task(_stream_worker_loop())


def stop_stream_worker() -> None:
    global _worker_task, _stream_queue
    if _worker_task and _stream_queue:
        _stream_queue.put_nowait({"stop": True})
        _worker_task = None


def _mark_stream_status(event_id: str, streamed: bool, error: str | None) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE dam_events SET streamed = ?, stream_error = ? WHERE event_id = ?",
            (1 if streamed else 0, error, event_id),
        )


async def _stream_worker_loop() -> None:
    """Sequential background worker for DB writes and streaming."""
    logger.info("dam_stream_worker_started (Async)")
    settings = get_settings()
    if _stream_queue is None:
        return
    while True:
        try:
            event = await _stream_queue.get()
        except Exception:
            break
            
        if event.get("stop"):
            _stream_queue.task_done()
            break

        event_id = event.get("event_id")
        
        # INSERT INTO DATABASE SEQUENTIALLY
        try:
            with get_db() as conn:
                previous_row = conn.execute("SELECT event_hash FROM dam_events ORDER BY id DESC LIMIT 1").fetchone()
                previous_hash = previous_row["event_hash"] if previous_row else ""
                
                canonical = _canonical_payload(event)
                event_hash = hashlib.sha256(f"{previous_hash}|{canonical}".encode("utf-8")).hexdigest()
                signature = _hmac_sign(event_hash)
                
                event["previous_hash"] = previous_hash
                event["event_hash"] = event_hash
                event["signature"] = signature
                
                conn.execute(
                    """
                    INSERT INTO dam_events (
                        event_id, event_type, severity, actor_user_id, actor_email, source_ip,
                        device_id, geo_country, geo_city, file_id, file_name, file_path,
                        action, status, message, metadata_json, created_at,
                        previous_hash, event_hash, signature, streamed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        event_id, event["event_type"], event["severity"], event["actor_user_id"],
                        event["actor_email"], event["source_ip"], event["device_id"],
                        event["geo_country"], event["geo_city"], event["file_id"],
                        event["file_name"], event["file_path"], event["action"],
                        event["status"], event["message"], json.dumps(event.get("metadata", {}), sort_keys=True),
                        event["created_at"], previous_hash, event_hash, signature
                    ),
                )
        except Exception as e:
            logger.error("Failed to insert dam_event id=%s: %s", event_id, e)

        try:
            _dispatch_alert_if_needed(event)
            
            # SIEM Rule Engine execution
            try:
                from .siem_engine import process_event_siem
                await process_event_siem(event)
            except Exception as e:
                logger.error("SIEM engine error: %s", e)

            # Push live to SOC Dashboard
            try:
                from ..routers.ws_alerts import broadcaster
                await broadcaster.broadcast({
                    "type": "alert",
                    **event
                })
            except Exception as e:
                logger.error("WebSocket broadcast failed: %s", e)
            
            if settings.log_stream_url:
                if not settings.log_stream_url.startswith("https://"):
                    raise ValueError("LOG_STREAM_URL must use https://")
                headers = {"Content-Type": "application/json"}
                if settings.log_stream_auth_token:
                    headers["Authorization"] = f"Bearer {settings.log_stream_auth_token}"
                async with httpx.AsyncClient(timeout=5.0, verify=settings.log_stream_verify_tls) as client:
                    response = await client.post(settings.log_stream_url, json=event, headers=headers)
                    response.raise_for_status()
            
        except Exception as exc:
            logger.warning("stream_event_failed event_id=%s error=%s", event_id, exc)
        finally:
            _stream_queue.task_done()



def _dispatch_alert_if_needed(event: dict[str, Any]) -> None:
    action = event.get("action", "")
    severity = str(event.get("severity", "low")).lower()
    if action not in ALERT_ACTIONS and severity not in {"high", "critical"}:
        return

    metadata = event.get("metadata", {})
    recipients = []
    owner_email = metadata.get("owner_email")
    if owner_email:
        recipients.append(owner_email)
    recipients.extend(get_settings().admin_alert_emails)
    recipients = [value for value in recipients if value]
    if not recipients:
        return

    summary = {
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "severity": event.get("severity"),
        "actor_email": event.get("actor_email"),
        "actor_user_id": event.get("actor_user_id"),
        "source_ip": event.get("source_ip"),
        "device_id": event.get("device_id"),
        "geo_country": event.get("geo_country"),
        "geo_city": event.get("geo_city"),
        "time": event.get("created_at"),
        "timezone": "UTC",
        "file": event.get("file_name"),
        "file_id": event.get("file_id"),
        "action": event.get("action"),
        "status": event.get("status"),
        "message": event.get("message"),
        "metadata": event.get("metadata", {}),
    }
    body = json.dumps(summary, indent=2)
    send_security_alert(
        subject=f"[DAM] {event.get('severity', 'info').upper()} {action}",
        body=body,
        recipients=recipients,
        include_telegram=severity in {"high", "critical"},
    )


def _queue_event_for_stream(event: dict[str, Any]) -> None:
    if _stream_queue is None:
        return
    try:
        _stream_queue.put_nowait(event)
    except asyncio.QueueFull:
        logger.warning("dam_stream_queue_full dropped_event_id=%s", event.get("event_id"))


def _detect_anomaly(
    conn,
    *,
    actor_user_id: int | None,
    source_ip: str | None,
    geo_country: str | None,
    event_hour: int,
) -> tuple[bool, str]:
    if not actor_user_id:
        return (False, "")

    recent = conn.execute(
        """
        SELECT created_at, geo_country
        FROM dam_events
        WHERE actor_user_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (actor_user_id,),
    ).fetchall()
    if len(recent) < 5:
        return (False, "")

    known_countries = {row["geo_country"] for row in recent if row["geo_country"]}
    off_hour = event_hour < 6 or event_hour > 22
    new_country = bool(geo_country and geo_country not in known_countries)

    if off_hour and new_country:
        return (True, "new geography and unusual hour")
    if new_country:
        return (True, "new geography")
    return (False, "")


def record_event(
    *,
    event_type: str,
    severity: str,
    action: str,
    status: str,
    message: str,
    actor_user_id: int | None,
    actor_email: str | None,
    request: Request | None = None,
    file_id: int | None = None,
    file_name: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = metadata or {}
    context = extract_request_context(request)
    geo = resolve_ip_geolocation(context["ip"])
    created_at = now_utc()
    risk_score, risk_factors = _calculate_risk_score(
        severity=severity,
        action=action,
        status=status,
        geo_country=geo.get("country"),
        actor_user_id=actor_user_id,
    )
    metadata = {**metadata, "risk_score": risk_score, "risk_factors": risk_factors}

    base_payload = {
        "event_type": event_type,
        "severity": severity.lower(),
        "actor_user_id": actor_user_id,
        "actor_email": actor_email,
        "source_ip": context["ip"],
        "device_id": context["device_id"],
        "geo_country": geo.get("country"),
        "geo_city": geo.get("city"),
        "file_id": file_id,
        "file_name": file_name,
        "file_path": file_path,
        "action": action,
        "status": status,
        "message": message,
        "metadata": metadata,
        "created_at": created_at,
    }

    # DB INSERT and hashing logic have been moved to _stream_worker_loop
    event_id = str(uuid.uuid4())
    event = {
        "event_id": event_id,
        **base_payload,
        "previous_hash": "",
        "event_hash": "",
        "signature": "",
    }
    _queue_event_for_stream(event)

    # Broadcast to all connected WebSocket clients (SOC dashboard)
    try:
        from ..routers.ws_alerts import broadcaster
        import asyncio

        ws_payload = {
            "type": "alert",
            "event_id": event_id,
            "event_type": event_type,
            "severity": severity.lower(),
            "action": action,
            "status": status,
            "message": message,
            "actor_email": actor_email,
            "actor_user_id": actor_user_id,
            "source_ip": context["ip"],
            "geo_country": geo.get("country"),
            "geo_city": geo.get("city"),
            "file_id": file_id,
            "file_name": file_name,
            "created_at": created_at,
            "metadata": metadata,
        }

        # Run async broadcast safely from synchronous context
        loop = None
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            pass

        if loop and loop.is_running():
            asyncio.ensure_future(broadcaster.broadcast(ws_payload))
        else:
            # Fallback: run in new event loop
            asyncio.run(broadcaster.broadcast(ws_payload))
    except Exception as _ws_err:
        logger.debug("ws_broadcast_skipped reason=%s", _ws_err)

    return event


def verify_event_integrity(event_id: str) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, event_id, event_type, severity, actor_user_id, actor_email,
                   source_ip, device_id, geo_country, geo_city, file_id, file_name,
                   file_path, action, status, message, metadata_json, created_at,
                   previous_hash, event_hash, signature
            FROM dam_events
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "reason": "event_not_found"}

        previous = conn.execute(
            "SELECT event_hash FROM dam_events WHERE id < ? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()

    payload = {
        "event_type": row["event_type"],
        "severity": row["severity"],
        "actor_user_id": row["actor_user_id"],
        "actor_email": row["actor_email"],
        "source_ip": row["source_ip"],
        "device_id": row["device_id"],
        "geo_country": row["geo_country"],
        "geo_city": row["geo_city"],
        "file_id": row["file_id"],
        "file_name": row["file_name"],
        "file_path": row["file_path"],
        "action": row["action"],
        "status": row["status"],
        "message": row["message"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "created_at": row["created_at"],
    }
    expected_previous = previous["event_hash"] if previous else ""
    expected_hash = hashlib.sha256(f"{expected_previous}|{_canonical_payload(payload)}".encode("utf-8")).hexdigest()
    expected_signature = _hmac_sign(expected_hash)

    return {
        "ok": row["previous_hash"] == expected_previous and row["event_hash"] == expected_hash and row["signature"] == expected_signature,
        "event_id": row["event_id"],
        "expected_previous_hash": expected_previous,
        "stored_previous_hash": row["previous_hash"],
        "expected_hash": expected_hash,
        "stored_hash": row["event_hash"],
    }
