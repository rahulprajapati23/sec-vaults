from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime
    role: str

class UploadResponse(BaseModel):
    id: int
    original_name: str
    expires_at: datetime
    download_count: int

class FileRecord(BaseModel):
    id: int
    original_name: str
    mime_type: str
    size_bytes: int
    created_at: datetime
    expires_at: datetime
    download_count: int
    max_downloads: Optional[int]
    shared_url: Optional[str] = None
