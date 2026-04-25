from __future__ import annotations
import json
import logging
from ..config import get_settings

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=True)

def get_logger() -> logging.Logger:
    settings = get_settings()
    logger = logging.getLogger("secure_file_storage")
    if logger.handlers:
        return logger

    logger.setLevel(settings.log_level.upper())
    formatter = JsonFormatter()
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    logger.propagate = False
    return logger
