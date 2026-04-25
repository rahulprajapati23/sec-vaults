from typing import Any, Optional
from pydantic import BaseModel

class StandardResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None

def success_response(data: Any = None) -> dict:
    return {"success": True, "data": data, "error": None}

def error_response(message: str, code: int = 400) -> dict:
    return {"success": False, "data": None, "error": message}
