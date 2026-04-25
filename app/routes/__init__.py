from __future__ import annotations

from fastapi import FastAPI
from . import (
    analytics,
    auth,
    auth_otp,
    dam,
    files,
    keycloak_iam,
    mfa,
    pages,
    reports,
    sessions,
    sharing,
    siem,
    system_utils,
    vault_access,
    ws_alerts,
)

ROUTER_MODULES = (
    pages,
    auth,
    auth_otp,
    mfa,
    files,
    sharing,
    sessions,
    dam,
    analytics,
    reports,
    vault_access,
    keycloak_iam,
    ws_alerts,
    system_utils,
    siem,
)

def include_all_routers(app: FastAPI) -> None:
    for module in ROUTER_MODULES:
        if hasattr(module, "router"):
            app.include_router(module.router)
