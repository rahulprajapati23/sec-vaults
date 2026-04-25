from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from .audit import get_logger
from ..database import get_db

logger = get_logger()

async def cleanup_loop() -> None:
    while True:
        try:
            logger.info("Cleanup running...")
        except Exception as exc:
            logger.error("cleanup_loop error: %s", exc)
        await asyncio.sleep(3600)

async def scheduled_reports_loop() -> None:
    while True:
        try:
            logger.info("Checking for scheduled reports...")
        except Exception as exc:
            logger.warning("reports_loop error: %s", exc)
        await asyncio.sleep(60)
