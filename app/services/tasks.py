from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from .audit import get_logger
from .files import delete_expired_files
from .retention import run_data_retention_cleanup
from .reports import send_daily_report, send_weekly_report
from ..database import get_db

logger = get_logger()

async def cleanup_loop() -> None:
    """Periodically clean up expired files and run data retention."""
    while True:
        try:
            with get_db() as conn:
                deleted = delete_expired_files(conn)
                run_data_retention_cleanup(conn)
            if deleted:
                logger.info("cleanup deleted=%s", deleted)
        except Exception as exc:
            logger.error("cleanup_loop_failed error=%s", exc)
        await asyncio.sleep(3600)


async def scheduled_reports_loop() -> None:
    """Fire daily/weekly reports at 00:00 UTC automatically."""
    last_daily: str | None = None
    last_weekly: str | None = None
    while True:
        now = datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        week = now.strftime("%Y-W%U")
        
        # Daily Report
        if now.hour == 0 and last_daily != today:
            try:
                send_daily_report()
                last_daily = today
                logger.info("scheduled_daily_report_sent date=%s", today)
            except Exception as exc:
                logger.warning("scheduled_daily_report_failed error=%s", exc)
        
        # Weekly Report (Monday)
        if now.weekday() == 0 and now.hour == 0 and last_weekly != week:
            try:
                send_weekly_report()
                last_weekly = week
                logger.info("scheduled_weekly_report_sent week=%s", week)
            except Exception as exc:
                logger.warning("scheduled_weekly_report_failed error=%s", exc)
        
        await asyncio.sleep(60)  # Check every minute
