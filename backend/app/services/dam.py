import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from ..config import get_settings
from ..database import get_db
from .audit import get_logger

logger = get_logger()
_stream_queue: Optional[asyncio.Queue[dict[str, Any]]] = None
_worker_task: Optional[asyncio.Task] = None

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

async def _stream_worker_loop() -> None:
    if _stream_queue is None: return
    while True:
        try:
            event = await _stream_queue.get()
            if event.get("stop"): break
            # Logic to process and store event
            _stream_queue.task_done()
        except Exception as e:
            logger.error("DAM worker error: %s", e)

def record_event(**kwargs) -> dict[str, Any]:
    event_id = kwargs.get("event_id") or str(uuid.uuid4())
    payload = {
        "event_id": event_id,
        "event_type": kwargs.get("event_type", "system"),
        "severity": kwargs.get("severity", "low"),
        "actor_user_id": kwargs.get("actor_user_id"),
        "actor_email": kwargs.get("actor_email"),
        "source_ip": kwargs.get("source_ip"),
        "action": kwargs.get("action", "unknown"),
        "status": kwargs.get("status", "success"),
        "message": kwargs.get("message", ""),
        "metadata_json": json.dumps(kwargs.get("metadata", {}), ensure_ascii=True),
    }

    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO dam_events (
                    event_id, event_type, severity, actor_user_id, actor_email,
                    source_ip, action, status, message, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["event_id"],
                    payload["event_type"],
                    payload["severity"],
                    payload["actor_user_id"],
                    payload["actor_email"],
                    payload["source_ip"],
                    payload["action"],
                    payload["status"],
                    payload["message"],
                    payload["metadata_json"],
                ),
            )
    except Exception:
        logger.debug("DAM event persistence skipped", exc_info=True)

    return {"status": "recorded", **payload}
