"""Supabase PostgreSQL database service for user data, logs, and files."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from supabase import Client, create_client

from ..config import get_settings


class SupabaseDB:
    """Supabase PostgreSQL client wrapper for DAM system."""

    _instance: SupabaseDB | None = None
    _client: Client | None = None

    def __new__(cls) -> SupabaseDB:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_client(cls) -> Client:
        """Get or initialize Supabase client (singleton)."""
        if cls._client is None:
            settings = get_settings()
            cls._client = create_client(settings.supabase_url, settings.supabase_anon_key)
        return cls._client

    @staticmethod
    def send_otp_email(email: str, otp: str) -> dict:
        """Send OTP to email via Supabase Auth."""
        client = SupabaseDB.get_client()
        try:
            response = client.auth.sign_in_with_otp({"email": email})
            return {"success": True, "message": "OTP sent", "session_id": response.session.id if response.session else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def verify_otp(email: str, token: str) -> dict:
        """Verify OTP token."""
        client = SupabaseDB.get_client()
        try:
            response = client.auth.verify_otp({"email": email, "token": token, "type": "email"})
            return {
                "success": True,
                "user": response.user.dict() if response.user else None,
                "session": response.session.dict() if response.session else None,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def create_user(email: str, password: str, metadata: dict | None = None) -> dict:
        """Create user with email and password."""
        client = SupabaseDB.get_client()
        try:
            response = client.auth.sign_up(
                {"email": email, "password": password, "options": {"data": metadata or {}}}
            )
            return {
                "success": True,
                "user_id": response.user.id if response.user else None,
                "user": response.user.dict() if response.user else None,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_user_by_email(email: str) -> dict | None:
        """Get user from database by email."""
        client = SupabaseDB.get_client()
        try:
            response = client.table("users").select("*").eq("email", email.lower()).execute()
            return response.data[0] if response.data else None
        except Exception:
            return None

    @staticmethod
    def insert_dam_event(event_data: dict) -> dict:
        """Insert DAM audit event to Supabase."""
        client = SupabaseDB.get_client()
        try:
            event_data["created_at"] = datetime.utcnow().isoformat()
            response = client.table("dam_events").insert(event_data).execute()
            return {"success": True, "event_id": response.data[0]["id"] if response.data else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def insert_file_metadata(file_data: dict) -> dict:
        """Insert file metadata to Supabase."""
        client = SupabaseDB.get_client()
        try:
            file_data["created_at"] = datetime.utcnow().isoformat()
            response = client.table("files").insert(file_data).execute()
            return {"success": True, "file_id": response.data[0]["id"] if response.data else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_user_files(user_id: str) -> list:
        """Get all files for a user."""
        client = SupabaseDB.get_client()
        try:
            response = client.table("files").select("*").eq("owner_id", user_id).execute()
            return response.data or []
        except Exception:
            return []

    @staticmethod
    def insert_login_log(log_data: dict) -> dict:
        """Insert login attempt log to Supabase."""
        client = SupabaseDB.get_client()
        try:
            log_data["timestamp"] = datetime.utcnow().isoformat()
            response = client.table("login_logs").insert(log_data).execute()
            return {"success": True, "log_id": response.data[0]["id"] if response.data else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_dam_events(user_id: str | None = None, limit: int = 100) -> list:
        """Get DAM audit events."""
        client = SupabaseDB.get_client()
        try:
            query = client.table("dam_events").select("*").order("created_at", desc=True).limit(limit)
            if user_id:
                query = query.eq("actor_user_id", user_id)
            response = query.execute()
            return response.data or []
        except Exception:
            return []

    @staticmethod
    def cleanup_old_records(table: str, days: int) -> dict:
        """Delete records older than specified days."""
        client = SupabaseDB.get_client()
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
            response = client.table(table).delete().lt("created_at", cutoff_date).execute()
            return {"success": True, "deleted_count": len(response.data) if response.data else 0}
        except Exception as e:
            return {"success": False, "error": str(e)}
