"""WebSocket real-time alerts broadcaster for the SOC dashboard."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/ws", tags=["websocket"])

# Global connection manager
class AlertsBroadcaster:
    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket):
        self._connections.discard(ws)

    async def broadcast(self, message: dict):
        """Broadcast to all connected clients, remove dead ones."""
        dead = set()
        payload = json.dumps(message)
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        self._connections -= dead

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# Singleton broadcaster — imported by services/dam.py to push events
broadcaster = AlertsBroadcaster()


@router.websocket("/alerts")
async def ws_alerts(ws: WebSocket):
    """
    WebSocket endpoint for the React SOC dashboard.
    Sends a welcome ping on connect, then streams live DAM events.
    """
    await broadcaster.connect(ws)
    try:
        # Send welcome message so frontend knows it's connected
        await ws.send_text(json.dumps({
            "type": "connected",
            "message": "Real-time alert stream connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "connections": broadcaster.connection_count,
        }))

        # Keep alive — receive pings from client
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=30)
                if data == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Send server keepalive
                await ws.send_text(json.dumps({"type": "heartbeat", "timestamp": datetime.now(timezone.utc).isoformat()}))
    except WebSocketDisconnect:
        broadcaster.disconnect(ws)
    except Exception as e:
        import logging
        logging.getLogger("uvicorn.error").error(f"WebSocket error: {e}")
        broadcaster.disconnect(ws)

