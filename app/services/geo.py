from __future__ import annotations

from typing import Any

import httpx
import ipaddress
from functools import lru_cache

from ..config import get_settings

@lru_cache(maxsize=1024)
def _fetch_geoip(ip_address: str) -> dict[str, str | None]:
    try:
        with httpx.Client(timeout=2.0, verify=True) as client:
            response = client.get(f"https://ipapi.co/{ip_address}/json/")
            response.raise_for_status()
            payload = response.json()
            return {
                "country": payload.get("country_name"),
                "city": payload.get("city"),
            }
    except Exception:
        return {"country": None, "city": None}

def resolve_ip_geolocation(ip_address: str | None) -> dict[str, str | None]:
    if not ip_address:
        return {"country": None, "city": None}
        
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {"country": "Local Network", "city": "Localhost"}
    except ValueError:
        pass # Not a valid IP

    settings = get_settings()
    if not settings.geolocation_enabled:
        return {"country": None, "city": None}

    return _fetch_geoip(ip_address)
