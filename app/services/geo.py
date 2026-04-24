from __future__ import annotations

from typing import Any

import httpx

from ..config import get_settings


def resolve_ip_geolocation(ip_address: str | None) -> dict[str, str | None]:
    if not ip_address:
        return {"country": None, "city": None}
    settings = get_settings()
    if not settings.geolocation_enabled:
        return {"country": None, "city": None}

    # Keep geolocation best-effort and non-blocking for primary business logic.
    try:
        with httpx.Client(timeout=2.0, verify=True) as client:
            response = client.get(f"https://ipapi.co/{ip_address}/json/")
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
            return {
                "country": payload.get("country_name"),
                "city": payload.get("city"),
            }
    except Exception:
        return {"country": None, "city": None}
