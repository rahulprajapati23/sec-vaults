from __future__ import annotations
import asyncio
import os
from datetime import datetime, timezone
from .audit import get_logger
from ..database import get_db
from .files import perform_virustotal_scan
from .dam import record_event
from ..config import get_settings

logger = get_logger()

async def cleanup_loop() -> None:
    while True:
        try:
            logger.info("Cleanup running...")
            # Implement cleanup logic here (e.g. deleting old files)
            with get_db() as conn:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("UPDATE files SET is_deleted = 1 WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
                conn.commit()
        except Exception as exc:
            logger.error("cleanup_loop error: %s", exc)
        await asyncio.sleep(3600)

async def scheduled_reports_loop() -> None:
    while True:
        try:
            logger.info("Checking for scheduled reports...")
            # Reports logic could go here
        except Exception as exc:
            logger.warning("reports_loop error: %s", exc)
        await asyncio.sleep(60)

async def virus_scan_loop() -> None:
    while True:
        try:
            logger.info("Scanning files for viruses...")
            with get_db() as conn:
                # Scan non-deleted files that aren't already marked infected
                rows = conn.execute("SELECT id, storage_path, original_name FROM files WHERE is_deleted = 0 AND (virus_scan_status IS NULL OR virus_scan_status = 'pending')").fetchall()
                for row in rows:
                    file_id = row["id"]
                    storage_path = row["storage_path"]
                    original_name = row["original_name"]
                    
                    if not os.path.exists(storage_path):
                        continue

                    logger.info(f"Performing deep scan for {original_name}...")
                    
                    # 1. Local signature check (fast)
                    is_infected = False
                    try:
                        with open(storage_path, "rb") as f:
                            sample = f.read(8192)
                            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in sample:
                                is_infected = True
                    except Exception as e:
                        logger.error(f"Failed to read file {storage_path}: {e}")
                        continue

                    # 2. VirusTotal Scan (if API key present)
                    settings = get_settings()
                    if not is_infected and settings.virustotal_api_key:
                        # Run sync function in thread pool
                        status = await asyncio.to_thread(perform_virustotal_scan, storage_path, file_id)
                        if status == "infected":
                            is_infected = True
                    
                    if is_infected:
                        logger.warning(f"MALWARE DETECTED: {original_name} (ID: {file_id}). DELETING.")
                        conn.execute("UPDATE files SET virus_scan_status = 'infected', is_deleted = 1 WHERE id = ?", (file_id,))
                        try:
                            os.remove(storage_path)
                            logger.info(f"Deleted infected file: {storage_path}")
                        except Exception as e:
                            logger.error(f"Failed to delete infected file {storage_path}: {e}")
                        
                        # Record security event
                        record_event(
                            event_type="security",
                            severity="critical",
                            action="malware_detected",
                            status="failure",
                            message=f"Malware found in {original_name} during continuous scan. File deleted.",
                            metadata={"file_id": file_id, "file_name": original_name}
                        )
                    else:
                        conn.execute("UPDATE files SET virus_scan_status = 'clean', virus_scan_timestamp = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), file_id))
                        # Record event for audit visibility if you want "everything logged"
                        record_event(
                            event_type="security",
                            severity="low",
                            action="malware_scan_complete",
                            status="success",
                            message=f"Malware scan completed for {original_name}. Result: CLEAN.",
                            metadata={"file_id": file_id, "file_name": original_name}
                        )
                conn.commit()
        except Exception as exc:
            logger.error("virus_scan_loop error: %s", exc)
        await asyncio.sleep(60) # Run every minute for "continuous" feel
